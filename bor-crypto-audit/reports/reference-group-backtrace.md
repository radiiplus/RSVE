# Reference Group Backtrace

## Reference Groups

The oracle uses the pinned BLS12-381 parameters in `internal/reference/oracle.go`.

- Base field modulus `p`: `1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`.
- Prime subgroup order `r`: `73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
- G1 curve: `y^2 = x^3 + 4` over `Fp`.
- G2 twist: `y^2 = x^3 + 4(1+i)` over `Fp2`, with `i^2 = -1` and representation `c0 + c1*i`.
- G2 serialization order: `x.c0 || x.c1 || y.c0 || y.c1`.

For either curve, the reference subgroup is the set of on-curve points annihilated by ordinary double-and-add multiplication by `r`:

```text
G1_ref = { P in E(Fp)   : [r]P = O }
G2_ref = { Q in E'(Fp2): [r]Q = O }
```

The point at infinity belongs to both groups. The standard generators and arithmetic are independently validated by the tests in `internal/reference/oracle_test.go`; the reference path does not call gnark subgroup checks or point multiplication.

## Trace Back From Result `1`

For EIP-2537, a pairing input is a nonempty concatenation of 384-byte tuples: 128 bytes of G1 followed by 256 bytes of G2. Bor's production path then:

1. Requires total input length to be a nonzero multiple of 384.
2. Decodes each 64-byte field element, requiring 16 leading zero bytes and a canonical value below `p`.
3. Decodes G1/G2 coordinates and checks each point is on its curve.
4. Calls `IsInSubGroup()` for each G1 and G2 point; failure returns the corresponding subgroup error.
5. Calls `PairingCheck` on the complete point arrays.
6. Returns a 32-byte word ending in `1` only when `PairingCheck` returns `(true, nil)`. A valid nonidentity pairing product returns a zero word without an error. In the extracted source, a `PairingCheck` error also leaves the zero word and returns it with a nil error.

Thus membership in `G1_ref` and `G2_ref` is necessary for reaching the pairing calculation, but it does not imply output `1`. The final condition is that the product of pairings across all tuples is the identity:

```text
product_i e(P_i, Q_i) = 1
```

## Observed Funnel

Counts below are differential cases from `reports/differential/report.json`, `reports/off-subgroup-sweep-report.json`, and `reports/curve-mutation-sweep-report.json`. The baseline contributes 44 point cases; its 10 field-element-only cases are excluded. The two sweep reports contribute 370 points.

| Stage | G1 | G2 | Total |
| --- | ---: | ---: | ---: |
| Point cases | 188 | 226 | 414 |
| Canonical coordinate encodings | 183 | 221 | 404 |
| Reference on-curve points | 178 | 212 | 390 |
| Reference subgroup points (`[r]P = O`) | 9 | 9 | 18 |
| Bor decoder accepts | 178 | 212 | 390 |
| gnark `IsOnCurve` true | 178 | 212 | 390 |
| gnark `IsInSubGroup` true | 9 | 9 | 18 |
| Production pairing `Run` returns no error | 9 | 9 | 18 |
| Single-case pairing output is `1` | 2 | 2 | 4 |

The 372 remaining canonical on-curve points are outside the reference subgroup. All were accepted by decoding and rejected by production `Run` at the corresponding subgroup check. Across unique comparable encodings, the blindspot report found zero points in either `gnark optimized domain - reference domain` or `reference domain - gnark optimized domain`, and zero production acceptances outside the reference domain. See `reports/blindspot-analysis.json` for exact members and tuple probes.

The final four `1` outputs are results for the harness's individual point-plus-standard-generator tuples. They are not a count of all identity-producing combinations. Batch 5 separately tested known identity and nonidentity products with the independent blst implementation.

## Reproduction

```sh
go run ./cmd/blindspots
go test ./...
```
