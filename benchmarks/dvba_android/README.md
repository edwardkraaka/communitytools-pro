# dvba_android — content-based binary routing benchmark

Self-contained benchmark suite pinning **Damn Vulnerable Android Bank** (`dvba.apk`,
sha256 `76c308fac6a655a3534771777780e004feb1d91be032857768c891b2baf40ba6`, 3,784,858
bytes — also pinned by `scripts/content-guard-binaries.json`). The artifact is the
ground truth; the suite exercises the binary tooling lane against it:

- `tools/artifact_format.py` content routing (magic bytes + zip member structure —
  the `apk` verdict must survive a rename to an extensionless file)
- the `artifact/v1` evidence-record contract emitted by `scripts/apk-pipeline.sh`

Discovered automatically by `benchmarks/run_benchmarks.py` (suite dir + `test_*.json`).
Two of the three cases run the dispatcher directly and need no credentials, network,
or device; the third is a source-reading assertion. Ground truth was derived by
inspection: single `classes.dex`, `AndroidManifest.xml`, four lib ABIs
(arm64-v8a/armeabi-v7a/x86/x86_64), no `BundleConfig.pb`.

Mirrors `benchmarks/php2shell`: one directory, pinned artifacts, loopback/no-network
execution, no bespoke runner integration.
