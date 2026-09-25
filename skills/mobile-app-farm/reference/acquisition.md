# Acquisition — fetching APKs/IPAs by id (no emulator, no ADB)

How the farm gets bytes. The workhorse is **`apkeep`** (EFF, Rust) for Android and **`ipatool`**
for iOS. Both are batch-friendly and driven from [`../../../scripts/apk-pipeline.sh`](../../../scripts/apk-pipeline.sh).

## Android — apkeep sources

| Source (`-d`) | Credentials | Notes |
|---------------|-------------|-------|
| `apk-pure` (default) | none | Fast, no account. First choice for triage. |
| `f-droid` | none | FOSS apps only. |
| `google-play` | Google email + **AAS token** | Production-faithful build; split APKs; needs the one-time token below. |
| `huawei-app-gallery` | none | Regional fallback. |

```bash
apkeep -a com.example.app -d apk-pure  ./raw                 # no creds
apkeep -a com.example.app -d google-play \
  -e "$GOOGLE_PLAY_EMAIL" -t "$GOOGLE_PLAY_AAS_TOKEN" \
  -o "split_apk=1,include_additional_files=1" ./raw          # authenticated
```

### One-time Google Play AAS token
Google Play needs an **AAS token** minted once from a Google account, then reused:

1. Get an OAuth token by signing in at the embedded-setup URL apkeep documents
   (`USAGE-google-play.md` in the apkeep repo) — yields an `oauth2_4/...` token.
2. Exchange it for a durable AAS token (apkeep's documented `aas_token` step / `gpapi`).
3. Store **only** in the gitignored `.env` (`.env.deepinfra`), sourced at container start:
   ```
   export GOOGLE_PLAY_EMAIL="acct@gmail.com"
   export GOOGLE_PLAY_AAS_TOKEN="aas_et/..."
   ```
   `.env.example` carries the placeholder; the real token is never committed.

Alternatives if Play integration hiccups: **`gplaydl`** (Python) or **`apkd`** (multi-source,
accepts a `packages.txt` with pinned versions).

There is **no Google Play download API / API key** — Google exposes no public download endpoint.
"Authenticated Google Play" means the Play Store protocol (gpapi) with a Google account; the
**AAS token is that account's reusable credential**, not an API key.

### Why Google Play, not just a mirror
Prefer Google Play whenever the build must be trustworthy:

- **Freshness** — mirrors (APKPure/F-Droid) can lag the store by days/weeks and occasionally
  serve a region-specific or older build. Google Play serves the **current** version for your
  account + device profile. For a pentest you almost always want the live production build.
- **Coverage** — **rare / unlisted / newly published apps are simply not on the mirrors.** Google
  Play is then the only source (subject to the account being able to see and acquire the app).

The pipeline therefore uses Google Play automatically when `GOOGLE_PLAY_*` are set, and treats a
mirror only as an **opt-in** fallback (`APK_SOURCE_FALLBACK=1`) so you never silently accept a
stale build.

### Account requirements & knobs
- The account must have **acquired** the app (free-install it once from that account, or purchase a
  paid app) — Play only serves apps in the account's library.
- `GOOGLE_PLAY_DEVICE` (default `px_3a`) picks the **device profile** Play matches the APK to;
  change it if a target ships architecture/SDK-restricted builds or reports "not available for your
  device". Region matters too — use an account whose country matches the target's availability.
- Use a **dedicated** Google account for bulk fetching (mass download can flag a primary account);
  the AAS token can expire or be revoked → re-mint via the steps above.

## Split bundles → one universal APK

apkeep (and Play) often return **split APKs / `.xapk` / `.apkm`** — `apktool` and `jadx` cannot
read those directly. The pipeline merges to a single universal APK with **APKEditor** before
decompiling:

```bash
java -jar /opt/APKEditor.jar m -i app.xapk -o base.apk        # bundle → universal
java -jar /opt/APKEditor.jar m -i ./raw     -o base.apk        # a dir of splits → universal
```

`APKEDITOR_JAR` overrides the jar path. If neither a single `.apk` nor a mergeable bundle is
found, the pipeline aborts (a zero-APK acquisition is a **failed acquisition**, not a pass).

## Integrity

Every acquisition records `sha256` (`apk.sha256`) and version (`apk.version` via `aapt dump
badging`) — the evidence anchor the engagement and any re-test key off.

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
