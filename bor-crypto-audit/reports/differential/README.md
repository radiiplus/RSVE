# Differential Run

Run `go run ./cmd/differential` to compare the checked-in corpus with the pinned Bor adapter, gnark-crypto v0.19.2 predicates, and the independent `math/big` reference. The command writes `report.json`; if it records a discrepancy, it also writes a minimized point and its complete pairing input under `minimized/`.

For G1 point cases, pairing `Run` receives the corpus point paired with the standard G2 generator. For G2 cases, it receives the standard G1 generator paired with the corpus point. A raw Fp element case is embedded as the G1 x-coordinate with y set to zero and paired with the standard G2 generator; the transformed bytes are recorded as `point_under_test_hex` and `pairing.input_hex`. Malformed lengths are passed through unchanged, so the precompile's length rejection is exercised.

`report.json` records decoding, curve membership, subgroup membership, pairing acceptance, and pairing output separately. `fuzz-results.json` records the subsequent G1 and G2 fuzz runs. A zero discrepancy count is a test result, not an exploitability determination.
