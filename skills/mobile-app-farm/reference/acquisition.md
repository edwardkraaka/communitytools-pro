# Acquisition — fetching APKs/IPAs by id (no emulator, no ADB)

How the farm gets bytes. The workhorse is **`gplaydl`** (authenticated Google Play — current build, split APKs, self-verifying) with **`apkeep`** (EFF, Rust) for credential-free mirrors and the legacy Play path, and **`ipatool`** for iOS. All batch-friendly, driven from [`../../../scripts/apk-pipeline.sh`](../../../scripts/apk-pipeline.sh).

## Android — sources

| Source | Credentials | Notes |
|--------|-------------|-------|
| `google-play` via **gplaydl** (preferred) | gplaydl dispenser key | Current build for a rotating real-device profile; split APKs + OBB; every artifact SHA-256-verified against Play's declared hashes at download time. |
| `google-play` via apkeep + AAS (legacy) | Google email + pre-minted AAS token | Works only with tokens minted before Sept 2026 — the OAuth mint is broken upstream (see below). |
| `apk-pure` via apkeep (default mirror) | none | Fast, no account. First choice for credential-free triage; may serve an OLDER build. |
| `f-droid` via apkeep | none | FOSS apps only. |
| `huawei-app-gallery` via apkeep | none | Regional fallback. |

```bash
gplaydl download com.example.app -o ./raw            # authenticated — current build, splits verified
gplaydl download com.example.app -o ./raw -a x86_64  # arch pin (e.g. acquiring for an emulator image)
apkeep -a com.example.app -d apk-pure ./raw          # no creds — mirror
```

### One-time gplaydl pairing
gplaydl links **your own Google account** through a one-time pairing:

1. Install gplaydl — already in the `kali-claude` image (`/opt/gplaydl-venv`, `/usr/local/bin/gplaydl`); on a clean host, an isolated venv (`pipx` / `python3 -m venv`) — Debian's system pip3 has a conflict on `typing_extensions`.
2. On any Android device, install the **gplaydl Authenticator app** (linked from the gplaydl repo) and sign in with the Google account you want to download as. It shows a rotating pairing code.
3. On the host: `gplaydl link --code "XXXX XXXX"` — pairs against the dispenser (dispenser.gplaydl.com) and writes `{dispenser, api_key}` to `~/.config/gplaydl/config.json`.
4. Farm/container path: copy that `api_key` into the gitignored `.env` as `GPLAYDL_API_KEY=` — the env var **fully overrides** the config file (gplaydl reads it first), which is what makes `docker run -e GPLAYDL_API_KEY=...` work inside a container with no pairing state.

The image ships **unpaired by design**: the installer layer runs as root before the user exists, and the config is per-HOME. Host pairing or `GPLAYDL_API_KEY` — those are the two auth states.

### Legacy: Google Play via apkeep + AAS token
apkeep's EmbeddedSetup OAuth browser mint **broke in September 2026** — Google's ToS page stalls without ever issuing the `oauth_token` cookie (apkeep issue #238 pattern). **Pre-minted AAS tokens still work** (issue #246): if you already have `GOOGLE_PLAY_EMAIL` / `GOOGLE_PLAY_AAS_TOKEN` in your `.env`, the pipeline honors them as a fallback lane when gplaydl is unavailable. When a token eventually expires or gets revoked, that is the moment to switch to the gplaydl pairing above rather than re-minting.

```bash
apkeep -a com.example.app -d google-play \
  -e "$GOOGLE_PLAY_EMAIL" -t "$GOOGLE_PLAY_AAS_TOKEN" \
  -o "split_apk=1,include_additional_files=1" ./raw   # legacy — pre-2026-09 tokens only
```

There is **no Google Play download API / API key** — Google exposes no public download endpoint. "Authenticated Google Play" means the Play Store protocol with your own linked account; the gplaydl dispenser key (and historically the AAS token) is that account link's reusable credential, not an API key.

### Why Google Play, not just a mirror
Prefer Google Play whenever the build must be trustworthy:

- **Freshness** — mirrors (APKPure/F-Droid) can lag the store by days/weeks and occasionally
  serve a region-specific or older build. Google Play serves the **current** version for your
  account + device profile. For a pentest you almost always want the live production build.
- **Coverage** — **rare / unlisted / newly published apps are simply not on the mirrors.** Google
  Play is then the only source (subject to the account being able to see and acquire the app).

The pipeline therefore prefers gplaydl automatically when `GPLAYDL_API_KEY` (or a host `~/.config/gplaydl/config.json`) is present, falls back to the apkeep+AAS lane when only `GOOGLE_PLAY_*` is set, and treats a mirror only as an **opt-in** fallback (`APK_SOURCE_FALLBACK=1`) so you never silently accept a stale build.

### Account requirements & knobs
- The linked account must have **acquired** the app (free-install it once from that account, or purchase a
  paid app) — Play only serves apps in the account's library.
- gplaydl **auto-rotates real device profiles** (Pixel-class), which reduces "not available for your
  device" friction; `GPLAYDL_ARCH` (`arm64` default; `x86_64` for emulator targets) still matters for
  architecture-restricted builds. Region matters too — link an account whose country matches the
  target's availability.
- Use a **dedicated** Google account for bulk fetching (mass download can flag a primary account);
  the dispenser key can be revoked or superseded — re-run the pairing to rotate it.
- `GPLAYDL_EXTRAS=1` also fetches OBB / asset packs (default off: GB-scale, unused by the static
  pipeline, and APKEditor's directory merge expects APKs only — curate the dir before merging).

## Split bundles → one universal APK

Play (and gplaydl in particular) return **split APKs** — `apktool` and `jadx` cannot
read those directly — and apkeep mirrors may return `.xapk` / `.apkm` bundles. The pipeline merges
to a single universal APK with **APKEditor** before decompiling:

```bash
java -jar /opt/APKEditor.jar m -i app.xapk -o base.apk        # bundle → universal
java -jar /opt/APKEditor.jar m -i ./raw     -o base.apk        # a dir of splits → universal
```

gplaydl lands loose splits named `<pkg>-<vc>.apk` / `<pkg>-<vc>-<split>.apk` directly in the
output dir — the same `$OUT/raw` directory merge handles them. `APKEDITOR_JAR` overrides the jar
path. If neither a single `.apk` nor a mergeable bundle is found, the pipeline aborts (a zero-APK
acquisition is a **failed acquisition**, not a pass).

## Integrity

Every acquisition records `sha256` (`apk.sha256`) and version (`apk.version` via `aapt dump
badging`) — the evidence anchor the engagement and any re-test key off. On the gplaydl lane the
download itself is additionally self-verifying: each artifact is hashed against Play's declared
digest at download time, so a corrupted or tampered-in-transit file fails the download rather
than silently landing in `raw/`.

## iOS — ipatool (static-only)

```bash
ipatool auth login -e "$APPLE_ID" -p "$APPLE_PASSWORD" --non-interactive
ipatool download -b com.example.app -o app.ipa
```

Batch bundle-id lists via the `ipatool-mass` wrapper. **Caveat:** App Store IPA binaries are
**FairPlay-encrypted** — you get the plist, entitlements, and metadata statically, but the Mach-O
needs decrypting on a **jailbroken device** (`bagbak` / `frida-ios-dump`) before code analysis.
That decrypt step is intentionally manual; see [`handoff.md`](handoff.md). Android is far friendlier
to this pipeline, which is why it is fully automated and iOS is static-only.
