#!/usr/bin/env bash
# fleet-lib.sh — shared library for the fleet runner (sourced, not executed).
# Fleet = N parallel interactive engagements over a targets file, driven through
# the existing kali-eng.sh / up.sh / kali-mon.sh stack. Reuses batch-pipeline.sh
# preflight semantics and kali-resume-entrypoint.sh idle/injection semantics.

STACK=/root/pentest-stack
FLEET_DIR="$STACK/fleet"
WS=/root/communitytools/projects/pentest       # = /workspace in containers
KALI_STATE=/root/kali-state
ENGAGE_REG="$STACK/engagements"
BOX_IP=REDACTED-BOX-IP
IMAGE=kali-claude-eng:latest

fleet_log() {  # fleet_log <runid> <msg...>
  printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$FLEET_DIR/$1/fleet.log" 2>/dev/null || true
}

fleet_notify() { [ -n "${NOTIFY_URL:-}" ] || return 0
  curl -s --max-time 10 -d "fleet: $*" "$NOTIFY_URL" >/dev/null 2>&1 || true; }

# ------------------------------------------------------------------ parsing --
normalize_target() {  # stdin url → stdout bare lowercase host (empty on invalid)
  sed -e 's~^[a-zA-Z][a-zA-Z0-9+.-]*://~~' -e 's~^[^@/]*@~~' \
      -e 's~[/?#].*$~~' -e 's~:[0-9]*$~~' | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]'
}

valid_host() { [[ "$1" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; }

default_tag() {  # batch-pipeline.sh derivation: 2 labels → first; else dots→dashes
  local dom=$1 first rest
  first=${dom%%.*}; rest=${dom#*.}
  if [[ "$rest" == *.* ]]; then echo "${dom//./-}"; else echo "$first"; fi
}

sanitize_tag() {  # lowercase, [a-z0-9-], cap 24
  local t; t=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '\n' | head -1)
  printf '%s' "${t:0:24}"
}

sanitize_instructions() {  # single paragraph: no newlines/controls, no idle-signature poison
  local s=$1
  s=$(printf '%s' "$s" | tr '\r\n\t' '  ' | tr -d '\000-\037')
  s=${s//;/; }
  if printf '%s' "$s" | grep -qiF 'esc to interrupt'; then
    echo "INSTRUCTIONS REJECTED: contains the idle-detector signature string" >&2; return 1
  fi
  printf '%s' "${s:0:2000}"
}

# parse_targets <file> <runid-or-""> [--allow-collide]
# → writes "tag\turl\tinstructions" lines to stdout; errors to stderr, exit 1.
# Collision with a registry entry this run doesn't own = hard error (kali-eng.sh
# would silently reuse that entry's pinned live session — never let it happen).
ltrim() { local s=$1; while [[ $s == [[:space:]]* ]]; do s=${s:1}; done; printf '%s' "$s"; }
rtrim() { local s=$1; while [[ $s == *[[:space:]] ]]; do s=${s%?}; done; printf '%s' "$s"; }
trim()  { rtrim "$(ltrim "$1")"; }

parse_targets() {
  local file=$1 runid=$2 allow=${3:-} lineno=0 tag url instr host
  local -A seen_url=() seen_tag=()
  while IFS= read -r line_raw || [ -n "$line_raw" ]; do
    lineno=$((lineno+1))
    line=$(trim "$line_raw")
    [ -z "$line" ] && continue
    [[ "$line" == \#* ]] && continue
    url=$(trim "${line%%|*}")
    if [[ "$line" == *\|* ]]; then
      instr=$(trim "${line#*|}")
    else
      instr=""
    fi
    host=$(printf '%s' "$url" | normalize_target)
    if ! valid_host "$host"; then
      echo "PARSE ERROR line $lineno: '$url' is not a bare domain/URL host" >&2; return 1
    fi
    if [ -n "${seen_url[$host]:-}" ]; then
      echo "PARSE ERROR line $lineno: duplicate target '$host'" >&2; return 1
    fi
    seen_url[$host]=1
    if [ -n "$instr" ]; then
      instr=$(sanitize_instructions "$instr") || return 1
    fi
    tag=$(sanitize_tag "$(default_tag "$host")")
    [ -n "$tag" ] || { echo "PARSE ERROR line $lineno: empty derived tag" >&2; return 1; }
    # ADOPTION (resume): if this run already holds a state file for this URL,
    # reuse ITS tag — a suffixed tag (wild-2) must resume as wild-2, never
    # re-collide and re-suffix to wild-3, which would duplicate the engagement.
    if [ -n "$runid" ]; then
      local sf ad_tag
      for sf in "$FLEET_DIR/$runid"/state/*.json; do
        [ -f "$sf" ] || continue
        if [ "$(jq -r '.url // empty' "$sf" 2>/dev/null)" = "https://$host" ]; then
          ad_tag=$(jq -r '.tag // empty' "$sf" 2>/dev/null)
          [ -n "$ad_tag" ] || continue
          [ -n "${seen_tag[$ad_tag]:-}" ] && { echo "PARSE ERROR line $lineno: state tag '$ad_tag' adopted twice" >&2; return 1; }
          seen_tag[$ad_tag]=1
          printf '%s\t%s\t%s\n' "$ad_tag" "https://$host" "$instr"
          continue 2
        fi
      done
    fi
    # collision inside the file
    if [ -n "${seen_tag[$tag]:-}" ]; then
      local n=2; while [ -n "${seen_tag[$tag-$n]:-}" ]; do n=$((n+1)); done
      tag="$tag-$n"
    fi
    # collision with the registry (unless this run owns it)
    if [ -f "$ENGAGE_REG/$tag.env" ]; then
      if [ -n "$runid" ] && [ -f "$FLEET_DIR/$runid/state/$tag.json" ]; then
        : # ours — adoptable
      elif [ -z "$allow" ]; then
        echo "PARSE ERROR line $lineno: tag '$tag' collides with registered engagement $ENGAGE_REG/$tag.env — rename it or pass --allow-collide" >&2; return 1
      else
        local n=2; while [ -f "$ENGAGE_REG/$tag-$n.env" ]; do n=$((n+1)); done
        tag="$tag-$n"
      fi
    fi
    seen_tag[$tag]=1
    printf '%s\t%s\t%s\n' "$tag" "https://$host" "$instr"
  done < "$file"
}

# -------------------------------------------------------------------- state --
state_file() { echo "$FLEET_DIR/$1/state/$2.json"; }

state_init() {  # state_init <runid> <tag> <url> <instructions>
  local f; f=$(state_file "$1" "$2")
  mkdir -p "$(dirname "$f")"
  # jq --arg throughout: instructions may contain quotes/backslashes — never
  # splice raw text into JSON (a `"` in per-target instructions would corrupt
  # the state file and crash the set -e runner).
  jq -n --arg tag "$2" --arg url "$3" --arg instr "$4" --arg now "$(date -Is)" \
    '{tag:$tag, url:$url, instructions:$instr, status:"queued",
      ts:{queued:$now}, container:("eng-"+$tag), attempts:0, injections:0,
      last_restart:0, last_event:"queued"}' > "$f"
}

set_instructions() {  # set_instructions <runid> <tag> <instr> — quote-safe update
  local f; f=$(state_file "$1" "$2")
  jq --arg i "$3" '.instructions=$i' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

update_event() {  # update_event <runid> <tag> <event> — quote-safe last_event write
  local f; f=$(state_file "$1" "$2")
  jq --arg ev "$3" '.last_event=$ev' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

state_set() {  # state_set <runid> <tag> <jq-expr>
  local f; f=$(state_file "$1" "$2")
  jq "$3" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

state_get() {  # state_get <runid> <tag> <jq-expr>  (e.g. .status)
  # always exit 0: a missing/corrupt state file reads as empty, never kills a
  # set -e caller (the runner would abort mid-poll with no log line).
  jq -r "$3" "$(state_file "$1" "$2")" 2>/dev/null || true
}

ts_age_s() {  # seconds since an ISO timestamp (empty → huge)
  [ -n "${1:-}" ] || { echo 999999999; return; }
  echo $(( $(date +%s) - $(date -d "$1" +%s) ))
}

eng_container() {  # eng_container <tag> — canonical container name for a tag.
  # docker compose renames a name-colliding container to <12hex>_eng-<tag> when
  # `up` re-renders the shared compose file mid-run (the Oct-2 mybatch loop: the
  # strict "^eng-$tag$" lookups missed it, the runner "adopted" a live container,
  # and every re-registration re-orphaned the previous generation). Resolve by
  # compose labels first — immune to renames — preferring a RUNNING match when
  # orphan generations share the label, then the exact name, then a name-suffix
  # scan. Prints the name (rc 0) or nothing (rc 1) — head never masks the miss.
  local tag=$1 n
  n=$(docker ps --filter "label=com.docker.compose.service=eng-${tag}" \
        --format '{{.Names}}' | head -1)
  [ -n "$n" ] && { echo "$n"; return 0; }
  docker inspect "eng-${tag}" >/dev/null 2>&1 && { echo "eng-${tag}"; return 0; }
  n=$(docker ps -a --filter "label=com.docker.compose.service=eng-${tag}" \
        --format '{{.Names}}' | head -1)
  [ -n "$n" ] && { echo "$n"; return 0; }
  n=$(docker ps -a --format '{{.Names}}' \
        | grep -E "(^|[0-9a-f]{12}_)eng-${tag}\$" | head -1)
  [ -n "$n" ] || return 1
  echo "$n"
}

eng_running() {  # eng_running <tag> — true iff the tag's container exists AND runs
  local n; n=$(eng_container "$1") || return 1
  [ -n "$n" ] || return 1
  [ "$(docker inspect -f '{{.State.Running}}' "$n" 2>/dev/null || echo false)" = true ]
}

# ----------------------------------------------------------------- preflight --
fleet_preflight() {  # fleet_preflight <gluetun> <envfile> <label>  (flock-serialized)
  { flock 8
    grep -qE '^(export )?ANTHROPIC_AUTH_TOKEN=..' "$2" 2>/dev/null \
      || { echo "PREFLIGHT FAIL ($3): no token in $2" >&2; return 1; }
    local running health ip avail
    running=$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)
    [ "$running" = true ] || { echo "PREFLIGHT FAIL ($3): $1 not running" >&2; return 1; }
    health=$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo none)
    [ "$health" != unhealthy ] || { echo "PREFLIGHT FAIL ($3): $1 unhealthy" >&2; return 1; }
    ip=$(docker run --rm --network "container:$1" --entrypoint bash "$IMAGE" \
          -c 'curl -s --max-time 20 https://api.ipify.org' 2>/dev/null)
    [ -n "$ip" ] || { echo "PREFLIGHT FAIL ($3): no egress through $1" >&2; return 1; }
    [ "$ip" != "$BOX_IP" ] || { echo "PREFLIGHT FAIL ($3): egress is the box IP — VPN LEAK" >&2; return 1; }
    avail=$(df -B1G --output=avail / | tail -1 | tr -d ' ')
    [ "$avail" -ge 5 ] || { echo "PREFLIGHT FAIL ($3): low disk (${avail}G)" >&2; return 1; }
    echo "PREFLIGHT OK ($3): egress $ip, ${avail}G free" >&2
  } 8>>"$FLEET_DIR/.preflight.lock"
}

memory_gate() {  # refuse launch if cap-sum would exceed 0.9×(RAM+swap); warn on overcommit
  local c cap_sum=0 ram swap limit
  for c in $(docker ps -a --filter name=^eng- --format '{{.Names}}'); do
    limit=$(docker inspect -f '{{.HostConfig.Memory}}' "$c" 2>/dev/null || echo 0)
    cap_sum=$(( cap_sum + limit ))
  done
  ram=$(free -b | awk '/^Mem:/{print $2}')
  swap=$(free -b | awk '/^Swap:/{print $2}')
  local cap_gb=$(( cap_sum / 1073741824 )) budget=$(( (ram + swap) * 9 / 10 ))
  if [ $(( cap_sum + 6442450944 )) -gt "$budget" ]; then
    echo "MEMORY GATE: eng-* cap-sum ${cap_gb}G + 6G would exceed 90% of RAM+swap — refusing to launch" >&2
    return 1
  fi
  [ "$cap_sum" -le "$ram" ] || echo "MEMORY WARN: eng-* cap-sum ${cap_gb}G exceeds physical RAM (over-commit; caps contain OOM)" >&2
  return 0
}

# ------------------------------------------------- artifacts (both layouts) --
# Engagement dirs exist BOTH at $WS/YYYYMMDD_<tag>_<phase>/ and (in-container
# relative-path quirk) $WS/projects/pentest/YYYYMMDD_<tag>_<phase>/ — glob both.
# Report census across every historical engagement: dirs end _active OR _web; the
# report itself is either a *technical*report*.md OR a branded *.pdf (generated
# from the transilience format). Matching any of those = engagement complete.
# NAME FALLBACK: the in-container claude names its engagement dir from the
# COMPANY name it derives, which need not contain the fleet tag (tag a-b-com
# can produce 20260921_120000_ab_osint). Those dirs are found via the tag's own transcript cwd
# ("cwd":"/workspace/projects/pentest/<dir>") — the authoritative record of
# where that session actually worked. Registry-tag uniqueness (parse_targets
# hard-errors on collisions) means a reused state dir = resumed engagement,
# so stale cwds matching is resume semantics, not a false positive.
tag_engagement_dirs() {  # <tag> <suffix> (e.g. _osint) → unique dir basenames; exit 0
  local f
  for f in "$KALI_STATE/$1"/claude/projects/-workspace/*.jsonl; do
    [ -f "$f" ] || continue
    grep -o '"cwd":"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4
  done | sort -u | while IFS= read -r d; do
    # WALK UP from recorded cwds: sessions mostly record SUBdir cwds (…/recon/repos)
    # that don't end in the suffix, and may truncate the tag in the dir name —
    # renzoprotocol's finished report was invisible to both matchers (Sep 23).
    case "$d" in /workspace/*) ;; *) continue ;; esac
    while [ -n "$d" ]; do
      case "$d" in *"$2") printf '%s\n' "${d##*/}"; break ;; esac
      d="${d%/*}"
    done
  done | sort -u
  return 0
}

osint_artifact() {  # → path or empty; never nonzero (set -e callers assign it every poll)
  local d base
  for d in "$WS" "$WS/projects/pentest"; do
    [ -e "$d"/*_"$1"_osint/reports/osint_report.md 2>/dev/null ] && { echo "$d"/*_"$1"_osint/reports/osint_report.md; return 0; }
    [ -e "$d"/*_"$1"_osint/reports/reconnaissance_report.md 2>/dev/null ] && { echo "$d"/*_"$1"_osint/reports/reconnaissance_report.md; return 0; }
  done
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    for d in "$WS" "$WS/projects/pentest"; do
      [ -e "$d/$base/reports/osint_report.md" ] && { echo "$d/$base/reports/osint_report.md"; return 0; }
      [ -e "$d/$base/reports/reconnaissance_report.md" ] && { echo "$d/$base/reports/reconnaissance_report.md"; return 0; }
    done
  done < <(tag_engagement_dirs "$1" "_osint")
  return 0
}

mobile_android_present() {  # <mobile-surface.json path> → 0 iff android verdict=present
  # Verdict gate for the stage-2 mobile lane. Never nonzero on bad JSON —
  # a corrupt/unreadable file is treated as not-present (web-only stage 2),
  # the same fail-safe direction as every other artifact helper.
  [ -n "${1:-}" ] && [ -f "$1" ] || return 1
  [ "$(jq -r '.android.verdict // "unclear"' "$1" 2>/dev/null)" = "present" ]
}

mobile_artifact() {  # → mobile-surface.json path or empty; never nonzero
  # The OSINT-phase mobile verdict (session-written, schema pinned in
  # osint_kickoff): android.verdict=present arms the stage-2 mobile lane.
  # Lookup mirrors osint_artifact: tag-named dirs in both layouts, then
  # brand-named dirs via recorded transcript cwds. Explicit for-loop over the
  # glob — multi-match must never fail with '[ -e f1 f2 ] too many arguments'.
  local d f base
  for d in "$WS" "$WS/projects/pentest"; do
    for f in "$d"/*_"$1"_osint/reports/mobile-surface.json; do
      [ -f "$f" ] && { echo "$f"; return 0; }
    done
  done
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    for d in "$WS" "$WS/projects/pentest"; do
      [ -f "$d/$base/reports/mobile-surface.json" ] && { echo "$d/$base/reports/mobile-surface.json"; return 0; }
    done
  done < <(tag_engagement_dirs "$1" "_osint")
  return 0
}

mobile_summary() {  # <mobile-surface.json path|empty> → one-line log verdict
  [ -n "${1:-}" ] || { echo "mobile: none (web-only)"; return 0; }
  jq -r '"mobile: " + (.android.verdict // "unclear") +
         (if ((.android.packages // []) | length) > 0
          then " (" + ((.android.packages)[0:2] | join(", ")) + ")"
          else "" end)' "$1" 2>/dev/null || echo "mobile: unreadable"
  return 0
}

active_artifact() {
  # DONE = a report DELIVERABLE in this tag's engagement reports/ dir:
  #   (a) any .pdf (renderer output is always the deliverable), or
  #   (b) an .md report whose name carries 'report' — excluding the osint-phase
  #       artifacts and process files (CIRs, scope notes, validation, roadmaps,
  #       skeptic briefs) that also live in reports/.
  # Filename-class survey across 40+ engagements chose the inclusion pair
  # (pdf | *report*.md minus exclusion list): the earlier exclusion-ONLY design
  # matched e17-c1-account-scope-report.md and CIR-device-access.md (interim
  # artifacts) as DONE markers. Explicit for-loop: multi-file globs must never
  # hit '[ -e f1 f2 ] too many arguments' (deepcoin's reports/ holds 4 matches).
  # Suffixes 'active web osint': an active phase continuing in the osint-phase
  # dir must still count (buyucoin-8h / deepcoin classes).
  local d sfx base rf bn
  for sfx in active web osint; do
    for d in "$WS" "$WS/projects/pentest"; do
      for rf in "$d"/*_"$1"_"$sfx"/reports/*; do
        [ -f "$rf" ] || continue
        bn=$(basename "$rf")
        case "$bn" in
          osint_report.md|reconnaissance_report.md|CIR-*|*account-scope*|priority-question*|roadmap*|engagement-validation.md|validation.md|skeptic-*) continue ;;
          *.pdf) echo "$rf"; return 0 ;;
          *report*.md) echo "$rf"; return 0 ;;
        esac
      done
    done
  done
  for sfx in active web osint; do
    while IFS= read -r base; do
      [ -z "$base" ] && continue
      for d in "$WS" "$WS/projects/pentest"; do
        for rf in "$d/$base"/reports/*; do
          [ -f "$rf" ] || continue
          bn=$(basename "$rf")
          case "$bn" in
            osint_report.md|reconnaissance_report.md|CIR-*|*account-scope*|priority-question*|roadmap*|engagement-validation.md|validation.md|skeptic-*) continue ;;
            *.pdf) echo "$rf"; return 0 ;;
            *report*.md) echo "$rf"; return 0 ;;
          esac
        done
      done
    done < <(tag_engagement_dirs "$1" "_$sfx")
  done
  return 0
}

# ------------------------------------------------------- liveness / injection --
transcript_bytes() {  # host-side mirror of the entrypoint ratchet for one tag
  # always exits 0 and prints a number (awk END): find failing on a missing dir
  # (fresh tag, no session files yet) must never abort a `set -e`-caller or
  # trigger `|| echo 0` double-emission under pipefail.
  { find "$KALI_STATE/$1/claude/projects" -name '*.jsonl' -printf '%s\n' 2>/dev/null || true; } \
    | awk '{s+=$1} END{print s+0}'
  return 0
}

pane_capture() {  # visible screen ONLY. 'esc to interrupt'/API banners live on the
  # live status line; scanning scrollback (-S -500) matched STALE hints from
  # finished turns and read parked sessions as busy — stage-2 injection then
  # stalled for up to an hour behind a signature long since scrolled off.
  dockx "$1" tmux capture-pane -pt eng 2>/dev/null || true
}

# dockx <container> <cmd…> — docker exec with a hard timeout wrapper. A docker
# exec against a wedged container endpoint can block INDEFINITELY (live case
# 2026-09-30: a send-keys into eng-<tag> hung 5h+, freezing the whole
# single-threaded runner loop — every slot's park/nudge/timeout ladder starved,
# finished targets sat unretired, queue starved). Every poll-path docker call
# must go through this. 30s: generous for capture-pane (instant) and send-keys
# (instant); anything longer is a stuck endpoint, treat as a failed probe.
dockx() { timeout 30 docker exec "$@"; }

pane_idle() {  # no in-flight turn, no error park
  local pane; pane=$(pane_capture "$1")
  printf '%s' "$pane" | grep -qiE 'esc to interrupt' && return 1
  printf '%s' "$pane" | grep -qiE 'API Error|Unable to connect|Retrying' && return 1
  return 0
}

pane_error_parked() {
  pane_capture "$1" | grep -qiE 'API Error|Unable to connect|Retrying'
}

# --- context/CMP observability: the autocompact rollout's eyes ----------------------
# Status-line wording IS the armed-state indicator (v2.1.197 binary): a configured
# window renders "NN% until auto-compact" (armed), unconfigured renders
# "NN% context used" (trigger disarmed = the pre-2026-09-23 fleet default, the
# 100%-context saturation root cause).
pane_context_pct() {  # <container> → prints 0-100 (0 = not visible/no percent shown).
  # `|| true` is load-bearing: grep-nomatch under pipefail would otherwise kill
  # every set -e caller the moment a pane renders no percentage (mid-turn, fresh
  # start) — the same trap that truncated fleet-metrics.sh's early rows.
  local m
  m=$(pane_capture "$1" | grep -oE '[0-9]+% (context used|until auto-compact)' | grep -oE '^[0-9]+' | tail -1 || true)
  echo "${m:-0}"
  return 0
}

pane_autocompact_armed() {  # <container> → 0 if armed ("until auto-compact" rendered)
  pane_capture "$1" | grep -q 'until auto-compact'
}

compact_count() {  # <tag> → number of compact summaries across ALL its session files;
  # never nonzero/never kills set -e callers (awk END prints a number regardless).
  { grep -h -c '"isCompactSummary":true' "$KALI_STATE/$1"/claude/projects/*/*.jsonl 2>/dev/null || true; } \
    | awk '{s+=$1} END{print s+0}'
  return 0
}

# inject_stage2 <container> <message> — the entrypoint's two-phase submission
inject_stage2() {
  local c=$1 msg=$2
  docker exec "$c" tmux send-keys -t eng -l -- "$msg" || return 1
  sleep 1
  docker exec "$c" tmux send-keys -t eng Enter || return 1
}

# Uptake: turn started = transcript growing or in-flight signature visible
injection_taken_up() {
  local c=$1 before=$2
  [ "$(transcript_bytes "$3")" -gt "$before" ] && return 0
  pane_capture "$c" | grep -qiE 'esc to interrupt'
}

# --------------------------------------------------------------- kickoffs --
osint_kickoff() {  # <url> <tag>
  # The engagement dir is NAMED (tag + timestamp): the Sep-27 f2pool slot found no
  # *f2pool* dir, adopted the newest visible OSINT dir (foundrydigital's), and spent
  # the slot on another target's engagement. Never leave "the engagement directory"
  # ambiguous again.
  local dir="/workspace/projects/pentest/$(date +%Y%m%d)_${2}_osint"
  printf 'Use the osint skill: run a complete passive OSINT engagement on %s. Create your engagement directory %s (this exact directory — it is yours; do NOT work in or modify any other engagement directory) and write everything there. Follow the coordination skill OUTPUT_STRUCTURE. Validate every discovered credential (single-shot read-only identity calls) and hand them off in session-memory.md. Consult the threat-intel skill (read /workspace/.claude/skills/threat-intel/SKILL.md): fingerprint the org'\''s stack (vendors, frameworks, libraries, wallet/key infrastructure), cross-match every identified technology and dependency version against the skill'\''s intel digest, and record each match as a numbered hunt hypothesis with its exploit sketch in a TI Hypotheses section of session-memory.md — the active phase executes these first. MOBILE-SURFACE CHECK (bounded, mandatory): determine whether this org publishes a mobile app — crawl the site for store-listing links (play.google.com/store/apps/details?id=…, apps.apple.com), direct-APK hrefs (*.apk served by the target itself), /.well-known/assetlinks.json, and app-store/news search by the org name. First write reports/mobile-surface.json BEFORE osint_report.md (write it in every case, even an absent or unclear verdict) using exactly: {"android":{"verdict":"present|absent|unclear","packages":["com.example.app"],"direct_apk":["https://target.example/app.apk"],"evidence":[{"url":"source-url","note":"why"}]},"ios":{"verdict":"present|absent|unclear","app_ids":["id123456"],"evidence":[{"url":"source-url","note":"why"}]}}. verdict=present requires evidence — a store package id, a target-served .apk URL, or assetlinks.json content; a blog mention alone is absent or unclear. The active phase acquires and analyzes the Android app ONLY on verdict=present, so this JSON is the mobile handoff. You are running unattended: never ask questions and never wait for user input. Always finish by writing reports/osint_report.md inside %s.' "$1" "$dir" "$dir"
}

stage2_message() {  # <url> <tag> <instructions> [osint-artifact-path] [mobile-json-path|-]
  local url=$1 tag=$2 instr=$3 art="${4:-}" mob="${5:-}"
  local extra="" where mobpara=""
  [ -n "$instr" ] && extra=" Per-target instructions: $instr."
  if [ -n "$art" ]; then
    # exact path — company-named engagement dirs don't contain the tag
    where="The OSINT report for this target already exists — read /workspace${art#$WS} and the session-memory.md in that engagement directory"
  else
    where="The OSINT report for this target already exists under projects/pentest/ — read the *_${tag}_osint engagement reports/osint_report.md and session-memory.md"
  fi
  # Mobile lane: armed ONLY by the OSINT-phase verdict (mobile-surface.json).
  # "-" = caller explicitly says no JSON (log verbosity use); empty = no JSON
  # found. Either way web-only stage 2. Bad JSON is treated as not-present —
  # the verdict gate must never crash the injected message builder.
  if [ -n "$mob" ] && [ "$mob" != "-" ] && mobile_android_present "$mob"; then
    mobpara=" MOBILE LANE (mandatory — this target ships an Android app): acquire the primary app into your engagement directory with the farm pipeline — run /workspace/scripts/apk-pipeline.sh <package-name> <engagement-dir>/mobile/ (it resolves gplaydl from GPLAYDL_API_KEY first, then apkeep mirrors; /workspace/scripts/apk-farm.sh batches several). Analyze the acquired artifacts with the mobile-security skill (load /workspace/.claude/skills/mobile-security/SKILL.md — scenarios, MASVS map, toolchain) and /workspace/scripts/apk-farm.sh farm-index.json for triage. Fold validated mobile findings into the technical report and the coverage matrix under the existing MAS-* classes — mobile findings are findings, same deliverables; a failed acquisition (404, key exhausted, region block) becomes a CIR under reports/client-input-requests/, never a silent skip. Cap the lane: primary app plus at most ONE additional app (the widest-permission secondary); record any further packages from the OSINT surface JSON in the report as discovered-but-not-analyzed. If the pipeline fell back to a mirror build, note the source and the stale-build caveat in the report."
  fi
  printf 'Use the pentest-engagement skill: run a full active penetration test on %s. %s first, including every validated credential. Hunt first: before breadth coverage, read the TI Hypotheses handed off in that session-memory.md and execute the intel-matched hypotheses as your first experiments (version-match exploits, incident-pattern replications per /workspace/.claude/skills/threat-intel/) — if none were handed off, form them by fingerprinting each asset'\''s stack against the threat-intel digest. The coverage matrix still completes; OWASP breadth is the completion layer, not the leading edge. If this is a crypto/web3 company, blockchain-security coverage is mandatory alongside the web classes. Drive every chain to real impact within RoE per the exploitation mandate: validate any newly discovered credentials single-shot, take injection findings to a bounded exfiltration proof, attempt a shell on every RCE-class finding, drive discovered SSH keys to a single-shot login attempt and wallet keys to a signed-message fund PoC (broadcast nothing, transfer nothing — the signature is the proof), pursue the end goal creatively — shell or box access by any path, admin/SSA access, sqli/data exfiltration, or financial harm — instead of stopping at detection, and quantify funds at risk for financial findings.%s%s Rules: active testing authorized; reversible writes on self-owned test accounts only; no DoS; no persistence; no credential brute force; egress already routes through the gluetun VPN netns already attached (verify the egress IP; never set up a VPN inside the container). You are running unattended: never wait for input; blockers become CIRs under reports/client-input-requests/. Always finish by writing the technical report in reports/.' "$url" "$where" "$mobpara" "$extra"
}

stage3_message() {  # <url> <tag> <engagement-dir-host-path> — phase-3 stitch mandate
  # Unattended mandate for the final phase. Lessons baked in: name the engagement
  # dir EXPLICITLY (a bare "write the report in reports/" lets the model read the
  # finished phase-2 report as work-complete and no-op), name the deliverable file
  # EXACTLY (the runner's stitch_artifact gate keys on it), and forbid rewriting
  # the finished technical report (append-only discipline).
  local url=$1 tag=$2 dir=$3
  local wdir="/workspace${dir#$WS}"   # container-side path (/workspace = $WS host-side)
  printf 'Use the attack-path-stitcher skill: STAGE 3 — FINAL MONETIZATION-PATH TASK on the same engagement (%s). The active pentest phase is COMPLETE — its technical report is final and must NOT be rewritten. This is new work in the existing engagement directory %s. Load the skill by reading /workspace/.claude/skills/attack-path-stitcher/SKILL.md (stitching rules, reference/, and tools/chain-merger.py live there; use the tool where its inputs exist, otherwise build the graph by hand per its schema). Stitch this engagement CONFIRMED single-asset findings into one ranked multi-hop chain demonstrating real end-to-end attacker impact — exactly one of: (1) a finance-adjacent fund-drain path: external entry point, then hops each citing the finding that enables it, ending at treasury/custody/hot-wallet/payment-payout funds, with funds at risk quantified — blockchain money-paths proven by SIGNED MESSAGE ONLY (broadcast nothing, transfer nothing; the signature is the proof); or (2) a monetizable database-exfiltration path: entry point, then hops, ending at the monetizable dataset (PII, credentials, financial records) with a bounded proof sample — at most 3 masked rows per endpoint, never mass extraction. Confirmed hops cite their findings; conditional hops are marked inferred. Rules unchanged: no DoS, no persistence, no brute force, single-shot credential validation, reversible writes on self-owned test accounts only; blockers become CIRs under reports/client-input-requests/. You are running unattended: never wait for input. ALWAYS finish by writing the ranked chain and impact quantification to %s/reports/monetization-chain.md — that exact file is the deliverable.' "$url" "$wdir" "$wdir"
}

stitch_artifact() {  # <tag> [engagement-dir-host-path] → path or empty; never nonzero
  # Phase-3 deliverable gate: reports/monetization-chain.md (exact basename).
  # Deliberately disjoint from active_artifact's pdf|*report* rule — the
  # phase-2 gate must not fire on the phase-3 deliverable and vice versa
  # (chain/stitch file names never contain 'report'). Lookup order mirrors the
  # other matchers: (a) the exact dir the runner recorded at arm time
  # (.stage3.dir — immune to the brand-vs-tag naming class), (b) any
  # tag-named engagement dir (suffix-agnostic: stitch work sometimes spawns
  # *_stitch dirs), (c) brand-named dirs via recorded transcript cwds.
  local d base f
  for d in "$2" "$WS" "$WS/projects/pentest"; do
    [ -n "$d" ] || continue
    for f in "$d"/reports/monetization-chain.md "$d"/*_"$1"_*/reports/monetization-chain.md; do
      [ -f "$f" ] && { echo "$f"; return 0; }
    done
  done
  while IFS= read -r base; do
    [ -z "$base" ] && continue
    for d in "$WS" "$WS/projects/pentest"; do
      [ -f "$d/$base/reports/monetization-chain.md" ] && { echo "$d/$base/reports/monetization-chain.md"; return 0; }
    done
  done < <(tag_engagement_dirs "$1" "_active")
  return 0
}

# ---------------------------------------------------------------- retirement --
# retire_engagement <tag> [archive-dir] — stop+rm the container, archive the
# registry entry, sync monitor+compose. No state-machine deps: usable for BOTH
# fleet-owned and manual engagements (any state transition is the caller's
# business). Never touches kali-state/ or workspace outputs.
retire_engagement() {
  local tag=$1 c="eng-$1" dest="${2:-}"
  if [ -n "$dest" ]; then mkdir -p "$dest"
  else mkdir -p "$ENGAGE_REG/retired-manual"; dest="$ENGAGE_REG/retired-manual"; fi
  docker stop -t 30 "$c" >/dev/null 2>&1 || true
  # rm can race the restart policy (restart-vs-remove wins nondeterministically):
  # retry until the container object is genuinely gone, else a stopped orphan
  # lingers with state=retired and its frozen monitor pane holds a grid spot.
  local try
  for try in 1 2 3; do
    docker rm "$c" >/dev/null 2>&1 || true
    docker ps -a --filter "name=^${c}$" --format '{{.Names}}' | grep -q . || break
    sleep 2
  done
  [ -f "$ENGAGE_REG/$tag.env" ] && mv "$ENGAGE_REG/$tag.env" "$dest/"
  bash "$STACK/up.sh" >/dev/null 2>&1 || true
  bash "$STACK/kali-mon.sh" --remove "$c" >/dev/null 2>&1 || true
}

# retire_target <runid> <tag> — fleet path: state-aware wrapper; guards against
# tags the run doesn't own (manual registry entries), then delegates.
retire_target() {
  local runid=$1 tag=$2
  # guard: this run's state must claim the tag (manual entries have no state
  # file in a run dir — the FLEET_RUN marker alone is not authoritative here)
  if [ "$(state_get "$runid" "$tag" '.tag')" != "$tag" ]; then
    fleet_log "$runid" "REFUSED retiring $tag — not owned by this run (no state file); use retire_engagement directly for manual entries"
    return 1
  fi
  fleet_log "$runid" "retiring $tag: stop+rm container, archiving registry entry"
  retire_engagement "$tag" "$FLEET_DIR/$runid/registry"
  state_set "$runid" "$tag" '.status="retired" | .ts.retired="'$(date -Is)'" | .last_event="retired"'
  fleet_log "$runid" "retired $tag (kali-state and workspace outputs preserved; re-attach: cp registry/$tag.env to engagements/ + up.sh)"
}
