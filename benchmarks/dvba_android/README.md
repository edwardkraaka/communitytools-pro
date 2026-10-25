# dvba_android — content-based binary routing benchmark

Self-contained benchmark suite pinning **Damn Vulnerable Android Bank** (`dvba.apk`,
sha256 `76c308fac6a655a3534771777780e004feb1d91be032857768c891b2baf40ba6`, 3,784,858
bytes — also pinned by `scripts/content-guard-binaries.json`). The artifact is the
ground truth; the suite exercises the binary tooling lane against it:

- `tools/artifact_format.py` content routing (magic bytes + zip member structure —
  the `apk` verdict must survive a rename to an extensionless file)
- the `artifact/v1` evidence-record contract emitted by `scripts/apk-pipeline.sh`

Discovered automatically by `benchmarks/run_benchmarks.py` (suite dir +
`test_content_routing.json`, matching its `test_*.json` glob). All three cases run
`tools/artifact_format.py` against the real `dvba.apk` (one against an extensionless
copy, to prove the verdict survives a rename) and assert on its JSON output — no
case merely reads source. Ground truth was derived by inspection: single
`classes.dex`, `AndroidManifest.xml`, four lib ABIs (arm64-v8a/armeabi-v7a/x86/x86_64),
no `BundleConfig.pb`.

Mirrors `benchmarks/php2shell`: one directory, pinned artifacts, loopback/no-network
execution, no bespoke runner integration.
