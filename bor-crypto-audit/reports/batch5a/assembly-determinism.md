# Assembly and Determinism Audit

## Question

Can the optimized amd64 pairing arithmetic or a generic fallback change the deterministic pairing result for the Batch 5A valid subgroup corpus?

## Runtime dispatch found in gnark-crypto v0.19.2

The active path is not selected by the pairing API itself. It reaches gnark's BLS12-381 Fp2 arithmetic in `internal/fptower`, whose amd64 assembly checks the package variable `supportAdx`. That variable is initialized from `utils/cpu.SupportADX`; in this release, ADX is enabled only when CPUID reports both ADX and BMI2. The host reports both features, and the runtime probe reported `SupportADX=true` and `SupportAVX512=true`.

`mulAdxE2` and `squareAdxE2` use ADX instructions on the supported path and branch to `mulGenericE2` / its generic square path otherwise. `noadx` forces the Fp2 tower flag false. The base-field `fp.Element` has its own amd64 assembly and separate ADX dispatch. The `purego` build tag selects generic base-field arithmetic, but does not itself remove the Fp2 tower assembly. The `purego,noadx` build exercises both the generic base-field and non-ADX Fp2 tower choices.

The standard `objdump` disassembler used here is GNU Binutils 2.42. The Go `go tool objdump` output rendered some ADX opcodes as unknown bytes, so the preserved object dumps below were produced with GNU `objdump`, which decoded `MULX`, `ADCX`, and `ADOX` correctly.

## Paired Build Results

The same seed and exact serialized corpus were run under five builds: default amd64 runtime dispatch, `noadx`, `purego`, `purego,noadx`, and `GOAMD64=v3`. Every build processed 91 cases / 5,032 tuples, returned no Bor errors, recorded no false acceptance or backend disagreement, and preserved all 24 metamorphic relations.

SHA-256 was byte-identical across all five builds for:

- Corpus: `c0704a882922f0e6227f90fb23a4cbaa172c2ddc83f671b7b2a22e04a0ea6a54`
- Differential results: `9d2bfadff0fe4e9787414d73335ccd32494bc69fae1462aeb2d6b884dc61a907`
- Metamorphic results: `d215e923505efa808ac19a411bd13f8cba9a567cd1821e2b705437c285ac0f29`

The machine-readable variant matrix is `assembly-variant-results.json`.

## Disassembly Artifacts

`disassembly/` preserves GNU objdump output from the linked default amd64 binary for:

- Bor adapter dependency call target `PairingCheck`.
- gnark `MillerLoop` and `FinalExponentiation`.
- Fp2 `mulAdxE2`, `squareAdxE2`, and generic `mulGenericE2`.
- Base-field `fp.mul`.
- The Fp2 multiply function from the `noadx` build, showing its runtime fallback call path.

In `fptower-mul-adx-amd64.txt`, the function loads `supportAdx`, branches to the generic implementation when it is false, and otherwise executes the ADX multiply/accumulate sequence. The `noadx` build sets the flag false. The `purego,noadx` execution confirms the composed fallback result on the tested corpus.

## Conclusion and Limits

No deterministic output difference was observed across the tested amd64 implementation variants. This is not a cross-CPU or cross-architecture proof: all runs used the same virtualized Intel Xeon host. A stronger hardware claim requires executing the same pinned input corpus on independent AMD64 CPUs and at least one supported non-amd64 architecture. This audit did not examine timing leakage or performance differences.

## Reproduction

From the `bor-crypto-audit/` directory:

```sh
go run ./cmd/batch5a -corpus-out /tmp/batch5a-default/corpus.json -reports-dir /tmp/batch5a-default/reports
go run -tags noadx ./cmd/batch5a -corpus-out /tmp/batch5a-noadx/corpus.json -reports-dir /tmp/batch5a-noadx/reports
go run -tags purego ./cmd/batch5a -corpus-out /tmp/batch5a-purego/corpus.json -reports-dir /tmp/batch5a-purego/reports
go run -tags 'purego noadx' ./cmd/batch5a -corpus-out /tmp/batch5a-generic/corpus.json -reports-dir /tmp/batch5a-generic/reports
GOAMD64=v3 go run ./cmd/batch5a -corpus-out /tmp/batch5a-v3/corpus.json -reports-dir /tmp/batch5a-v3/reports
objdump -d --disassemble='github.com/consensys/gnark-crypto/ecc/bls12-381/internal/fptower.mulAdxE2.abi0' /tmp/bor-batch5a-default
```
