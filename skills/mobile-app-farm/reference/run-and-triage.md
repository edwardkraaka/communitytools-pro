# Running the farm + reading the triage

Operational detail for [`../../../scripts/apk-pipeline.sh`](../../../scripts/apk-pipeline.sh) and
[`../../../scripts/apk-farm.sh`](../../../scripts/apk-farm.sh). Acquisition sources are in
[`acquisition.md`](acquisition.md); the pentest handoff is in [`handoff.md`](handoff.md).

## Toolchain (baked into the `kali-claude` image)

`scripts/kali-claude-setup.sh` installs: `apkeep`, `jadx`, `apktool`, `androguard`, `ripgrep`,
`openjdk`, `android-sdk-platform-tools` (adb), `APKEditor.jar` (`/opt/APKEditor.jar`), `ipatool`.
Verify inside a container:

```bash
apkeep --version && jadx --version && apktool --version && androguard --help >/dev/null && rg --version
```

## MobSF — sibling container, not in the image

MobSF is heavy and self-contained, so it runs as its **own container** reached over REST. Use the
repo launcher ([`../../../scripts/mobsf-up.sh`](../../../scripts/mobsf-up.sh)):

```bash
bash scripts/mobsf-up.sh            # or: MOBSF_IMAGE=<other-digest> / MOBSF_PORT=8000 overrides
```

It pins a tested image digest (re-pin deliberately, never `:latest`), keeps scans in the named
volume `mobsf-data` so they survive re-creation, restarts with the daemon (`unless-stopped`), and
holds a stable REST key by way of `-e MOBSF_API_KEY`. The container publishes **only the docker0
bridge IP** (default `172.17.0.1:8000`) — reachable from the host and from default-bridge
`docker run` hops, yet never from outside the box, which matters because MobSF's web UI is
unauthenticated. The key resolves from `./.env` (`MOBSF_KEY=`), an explicit argument, or
`$MOBSF_API_KEY`, and is auto-generated + written back to `.env` when absent (a bare
`docker run -p 8000:8000` instead publishes an unauthenticated UI on every interface).

Then point the pipeline at it:

```bash
MOBSF_URL=http://172.17.0.1:8000 MOBSF_KEY=<same key> bash scripts/apk-pipeline.sh com.example.app engagement/com.example.app
```

When `MOBSF_URL` is unset the pipeline simply skips MobSF — `triage.md` (below) still gives the
agent plenty to work with.

## Batch run

```bash
printf 'com.a\ncom.b\ncom.c\n' > packages.txt      # one package per line; # comments ok
scripts/apk-farm.sh packages.txt engagement 3       # 3 concurrent pipelines
```

- **Resumable:** an app whose `engagement/<pkg>/apk.sha256` exists is skipped, so re-runs only
  fetch what's missing (or newly added).
- Each app's stdout/stderr goes to `engagement/<pkg>.log`; failures are reported, not fatal to the batch.
- `engagement/farm-index.json` aggregates one row per app: `version`, `sha256`, `endpoints` count,
  and MobSF severity counts when a report exists — the agent's worklist.

## What `triage.md` contains

Fast, deterministic signal the agent reads first (never the final word — it drives the manual pass):

- **Manifest** — `uses-permission`, `android:exported` components, custom `android:name`s
  (via `androguard axml`, falling back to the apktool-decoded manifest).
- **URLs / endpoints** — every `https?://…` in `jadx/` output (deduped). These seed the
  **backend-API** web asset — see [`handoff.md`](handoff.md).
- **Hardcoded-secret heuristics** — `api_key|secret|token|password|bearer = "…"` matches over
  `jadx/sources`. High false-positive by design; **verify before reporting** (a real key must be
  live-validated with a read-only identity probe, per the `osint`/validation rules).

## Obfuscated / packed apps

`jadx --deobf` tolerates partial failure (partial source is still useful; errors → `jadx.errors.log`).
If `apkid` fingerprints a packer/DexGuard, unpack first
([`../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md`](../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md)),
then re-run. Flutter / Unity / React-Native bundles need runtime-aware decompilers — route those to
[`../../mobile-security/reference/android-static-analysis.md`](../../mobile-security/reference/android-static-analysis.md).
