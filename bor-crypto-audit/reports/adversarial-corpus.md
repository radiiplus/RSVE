# Deterministic Adversarial Corpus

The serialized corpus is `testdata/bls12-381-corpus.json` (54 cases; SHA-256 `3b7312b16d32ff373e726975f302abc3c72cda99fa3d4d15d613b539a52e9614`). Generate it with `go run ./cmd/corpusgen`; the command writes the same JSON for the fixed seed on each run. `internal/corpus` exposes `Build` and `Marshal` for reuse.

Each case stores its curve, kind, byte length, exact input bytes as lowercase hex, generation description, and mathematical classification. The document records seed `bor-crypto-audit/bls12-381/corpus/v1` and the SHA-256 counter-stream derivation. All point classifications use the independent `internal/reference` oracle: coordinates are checked for canonicality and curve membership, then subgroup membership is decided by ordinary `[r]P` scalar multiplication.

Coverage includes `0`, `1`, `p-1`, `p`, `p+1`, and the maximum 384-bit field encoding; nonzero high 16 bytes; malformed field and point lengths; the same field boundaries embedded in G1 and G2 coordinates; standard generators and fixed plus seeded scalar multiples; the EIP all-zero infinity encoding; degenerate and off-curve coordinates; and G2 coordinate/coefficient swaps.

The G1 and G2 off-subgroup cases are sampled directly from the full curve: deterministic x-coordinates are tested until `x^3+4` or `x^3+4(1+i)` has a square root, then the resulting on-curve point is classified by `[r]P`. This does not use hash-to-curve or cofactor clearing. The resulting encodings and expected classifications are stored in the JSON, so later checks do not need to repeat sample generation.

Validation: `go test ./internal/corpus ./internal/reference` checks deterministic serialization, required boundary cases, valid subgroup classifications, off-subgroup classifications, and off-curve cases.
