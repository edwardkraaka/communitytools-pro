---
name: mobile-app-farm
description: Batch, scriptable acquisition of Android APKs (and iOS IPAs) by package/bundle id — fetch (apkeep / ipatool, no emulator or ADB), normalize split bundles, decompile (jadx/apktool), triage (permissions, endpoints, secrets, MobSF), and hand the decompiled source to mobile-security for the MASVS pentest. Use to pentest many apps as source, at scale.
---

# Mobile App Farm

Turn a **list of package names** into a directory of **decompiled source + triage** an agent can
pentest — replacing the manual "install on emulator → repack → adb pull" loop with three scripts.
It **acquires and prepares**; the actual MASVS testing is [`mobile-security`](../mobile-security/SKILL.md).

## When to use

- You have one or many **Android package names** (or iOS bundle ids) and want their source without
  a device — bug-bounty triage, a portfolio of apps, or a single deep target.
- You want the recovered code + endpoints in front of the agent so it can review logic, find
  secrets, and drive the **backend API** the app talks to.

## The three scripts (`scripts/`)

| Script | Does |
|--------|------|
| [`apk-pipeline.sh`](../../scripts/apk-pipeline.sh) | One app: apkeep acquire → APKEditor merge (splits/XAPK) → apktool + jadx → `triage.md` → optional MobSF |
| [`apk-farm.sh`](../../scripts/apk-farm.sh) | Batch a `packages.txt` through the pipeline (bounded-parallel, resumable) → `farm-index.json` |
| [`ipa-pipeline.sh`](../../scripts/ipa-pipeline.sh) | iOS **static-only**: ipatool download → Info.plist/entitlements/strings (FairPlay decrypt is manual) |

```bash
# single Android app (no credentials — APKPure)
scripts/apk-pipeline.sh com.example.app engagement/com.example.app

# a whole list, 3 at a time
printf 'com.a\ncom.b\ncom.c\n' > packages.txt
scripts/apk-farm.sh packages.txt engagement 3
```

Optional env (all off by default): `GOOGLE_PLAY_EMAIL` + `GOOGLE_PLAY_AAS_TOKEN` (authenticated
Play), `MOBSF_URL` + `MOBSF_KEY` (MobSF scan), `APPLE_ID` + `APPLE_PASSWORD` (ipatool). Real values
live only in the gitignored `.env` — see [`reference/acquisition.md`](reference/acquisition.md).

## Output layout (per app)

```
engagement/<pkg>/
  raw/…            apkeep download(s)
  base.apk         universal APK (merged if the source was split/XAPK)
  apk.sha256       integrity anchor
  apk.version      versionName (aapt)
  apktool/         manifest, resources, smali
  jadx/sources/    Java/Kotlin source    ← the agent reviews this
  triage.md        permissions · endpoints · secret heuristics
  mobsf-report.json  (only if MOBSF_URL set)
engagement/farm-index.json   one row per app (version, sha, endpoints, MobSF severity counts)
```

## Then pentest it

Point the agent at `jadx/sources` + `triage.md` (+ `mobsf-report.json`) and run
[`mobile-security`](../mobile-security/SKILL.md) for the MASVS finding pass. **The backend API
recovered from the bundle is a separate web asset** with its own surface and the ordinary web
classes — a farm that only tests the bundle leaves the real risk untested. Full handoff (incl.
optional `mobile-surface.json` for coverage-mode engagements):
[`reference/handoff.md`](reference/handoff.md). Running/triage detail:
[`reference/run-and-triage.md`](reference/run-and-triage.md).

## Toolchain

`apkeep`, `jadx`, `apktool`, `androguard`, `ripgrep`, `APKEditor.jar`, `ipatool` ship in the
`kali-claude` image (`scripts/kali-claude-setup.sh`); **MobSF runs as a sibling container** reached
over its REST API at `MOBSF_URL`. Install/run detail: [`reference/run-and-triage.md`](reference/run-and-triage.md).

## Authorization

Batch acquisition tooling (apkeep is EFF's) is fine for research, but **only test apps you are
authorized to assess or that are in bug-bounty scope.** Acquisition ≠ authorization to attack.
