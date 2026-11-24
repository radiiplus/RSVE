# Batch 5A Final Assessment

**NO DISCREPANCY FOUND IN TESTED SCOPE**

## Evidence

- Corpus seed: `bor-crypto-audit/bls12-381/batch5a-pairing-products/v1`
- Corpus: `testdata/batch5a/pairing-products.json`
- Cases: 91; total tuples processed across cases: 5032
- Bor Run errors: 0
- Backend disagreements: 0
- Metamorphic backend relations: 24; all preserved: true
- Mathematically false Bor output-1 acceptances: 0
- Bor source: develop commit `cefbcfd4078e7a6cdb8e7642bc26e3589e05e7ab`
- gnark-crypto: `v0.19.2`; blst: `v0.3.17`

Classification compares the complete 32-byte Bor result word to canonical zero and one words. A no-error call returning zero is a successful nonidentity equation, not proof acceptance. Implementation disagreements without a false Bor acceptance remain backend/consensus observations and do not justify an economic witness. Batch 6 was not run by this command. Assembly variant results and linked disassembly are documented separately in `assembly-determinism.md`.

## Reproduction

```sh
go run ./cmd/batch5a
go test ./...
go mod verify
```
