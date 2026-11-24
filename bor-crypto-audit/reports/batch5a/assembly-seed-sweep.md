# Assembly Path Seed Sweep

## Result

Three additional deterministic corpus seeds were run through both the default amd64 build and the combined `purego,noadx` build. The latter selects generic base-field arithmetic and the non-ADX Fp2 tower path. All six runs processed 91 cases and 5,032 tuples each, reported zero Bor errors, zero false acceptances, zero backend disagreements, and preserved all 24 metamorphic relations.

For each seed, the default and generic builds produced byte-identical differential and metamorphic reports. Metamorphic results were also identical across all seeds. This expands the same-host comparison by 30,192 tuple executions (15,096 in each build family).

| Seed | Differential report SHA-256 | Metamorphic report SHA-256 | Default equals generic |
| --- | --- | --- | --- |
| `hardware-sweep-alpha` | `1b39fb577c979b02236088a9ec0265464ad024bfb19eec8aa4ee6de97d802010` | `d215e923505efa808ac19a411bd13f8cba9a567cd1821e2b705437c285ac0f29` | yes |
| `hardware-sweep-beta` | `89f17919bd02d97cfaa44db67e122209d05d3f24a808f8f75d36efbab46f7b51` | `d215e923505efa808ac19a411bd13f8cba9a567cd1821e2b705437c285ac0f29` | yes |
| `hardware-sweep-gamma` | `3f55e692023ecf034de74f578e4eddcfaa7395ec191b676367bfbf481be875d9` | `d215e923505efa808ac19a411bd13f8cba9a567cd1821e2b705437c285ac0f29` | yes |

## Reproduction

Run from the repository root:

```sh
for seed in hardware-sweep-alpha hardware-sweep-beta hardware-sweep-gamma; do
  go run ./cmd/batch5a -seed "$seed" -corpus-out "/tmp/$seed/corpus.json" -reports-dir "/tmp/$seed/default"
  go run -tags 'purego noadx' ./cmd/batch5a -seed "$seed" -corpus-out "/tmp/$seed/generic-corpus.json" -reports-dir "/tmp/$seed/generic"
  cmp "/tmp/$seed/default/differential-results.json" "/tmp/$seed/generic/differential-results.json"
  cmp "/tmp/$seed/default/metamorphic-results.json" "/tmp/$seed/generic/metamorphic-results.json"
done
```

The corpus generator uses deterministic SHA-256 counter streams. The recorded hashes above were computed from the default-build differential report; `cmp` confirmed the corresponding generic-build output was identical.

## Scope

This strengthens evidence that the optimized and generic implementations agree over additional valid-subgroup scalar products on the tested amd64 host. It does not compare independent physical CPUs or architectures, nor does it test timing, gas, microarchitectural effects, or EVM state execution. No economic candidate was produced, so Batch 6 remains gated.
