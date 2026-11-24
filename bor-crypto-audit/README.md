# Bor Crypto Audit

Standalone, reproducible analysis of Bor's BLS12-381 pairing precompile. This project does not clone the complete Bor repository or modify Bor production code.

## Pins

- Bor develop: `cefbcfd4078e7a6cdb8e7642bc26e3589e05e7ab`
- Bor release (`v2.11.0`): `3a018e38467594508ca31ebeaf804837fb92834a`
- `github.com/consensys/gnark-crypto`: `v0.19.2`
- Independent pairing cross-check: `github.com/supranational/blst v0.3.17`

The four upstream files per snapshot are kept under `source/`. Their Git blob IDs and SHA-256 hashes are recorded in `reports/source-manifest.json`. The pairing adapter is generated from AST-selected declarations in the pinned develop snapshot.

## Findings

The independent `math/big` oracle defines subgroup membership by ordinary double-and-add `[r]P = O`. Differential checks found no disagreement between that reference, gnark's optimized subgroup predicate, Bor decoding, and Bor's production pairing `Run` in the tested inputs.

The original corpus plus deterministic full-curve and curve-aware mutation sweeps contain 372 unique canonical on-curve off-subgroup points. Bor decodes them and rejects them at the relevant subgroup check. The pairing cross-check found no disagreement for the valid pairing vectors. No credible false pairing acceptance was demonstrated, so the Batch 6 escrow/EVM witness was not run; see `reports/batch6-gate.json`.

Batch 5A checked 91 bilinearity-derived pairing products across 5,032 tuples, including batches through 256 tuples. The independent scalar-product oracle, Bor production path, direct gnark, and blst agreed on every tested identity result; no false acceptance or backend disagreement was found. Eight algebraic metamorphic relations were also checked within each backend, covering tuple order, term splitting, scalar transfer, cancellation, and infinity. Details are in `reports/batch5a/`.

An amd64 build-path follow-up compared default dispatch, `noadx`, `purego`, `purego,noadx`, and `GOAMD64=v3`; corpus, differential, and metamorphic report hashes were identical. GNU objdump artifacts for the pairing and field-arithmetic symbols are in `reports/batch5a/disassembly/`. These runs used one VM host and do not establish cross-architecture equivalence.

The set differences, intersections, and tuple-order probes are in `reports/blindspot-analysis.json`. The mathematical reference-group definition and backward trace from pairing output `1` are in `reports/reference-group-backtrace.md`.

## Reproduction

Requires Go `1.26.11` as declared in `go.mod`.

```sh
go test ./...
go mod verify
go run ./cmd/corpusgen
go run ./cmd/offsubgroup-sweep -per-group 128
go run ./cmd/curve-mutation-sweep -max-delta 16
go run ./cmd/differential -corpus testdata/off-subgroup-sweep.json -out reports/off-subgroup-sweep-report.json
go run ./cmd/differential -corpus testdata/curve-mutation-sweep.json -out reports/curve-mutation-sweep-report.json
go run ./cmd/blindspots
go run ./cmd/batch5a
```

The existing reports also include the original differential corpus and independent pairing comparisons. Zero discrepancies describe the tested cases; they are not a proof over every possible input.
