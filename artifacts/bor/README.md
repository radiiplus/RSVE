# Bor Analysis Artifacts

These JSON files are the focused Bor observations and RSVE result log for
commit `c72e248587a19b1c93eda95871c46b53071e58fd`.

- `bor-balance-analysis.json`: production balance, state-root, and receipt
  observations from the focused transaction harness.
- `bor-storage-root-probe.json`: the separate serial/parallel storage-root
  differential artifact.
- `bor-callwithstate-probe.json`: production observation of a caller-owned
  read-only call advancing nonce `7 -> 8` without a canonical transaction or
  receipt.
- `autonomous-analysis.json`: combined RSVE output. It includes the observed
  nonce path and the modeled `StateOverride.Apply` balance/storage candidate,
  with unresolved process, kernel, memory/CPU, and external persistence
  regions retained.

The artifacts are evidence records, not claims that the modeled state-override
candidate has been replay-validated against a clean Bor checkout.
