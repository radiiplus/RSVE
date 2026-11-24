# Batch 5A Methodology

## Question and decision rule

Test whether Bor's extracted production pairing precompile returns a successful call with output `1` when the mathematical pairing product is not the identity, using only canonical, on-curve, correctly subgroup-classified points. A successful call returning the 32-byte zero word is a valid nonidentity pairing result, not proof acceptance.

For known generators `P0` in G1 and `Q0` in G2, generate each tuple as `P_i = [a_i]P0`, `Q_i = [b_i]Q0`. By bilinearity and the prime order `r` of the target subgroup:

```text
product_i e(P_i, Q_i)
= product_i e(P0, Q0)^(a_i*b_i)
= e(P0, Q0)^(sum_i a_i*b_i)
```

Because the generator pairing is nondegenerate and has order `r`, the expected product is the identity exactly when `sum_i(a_i*b_i) mod r == 0`. This scalar-product result is the mathematical oracle; it is not derived from gnark, blst, or Bor outputs.

## Point construction and validation

Use the standard BLS12-381 generators and the independently implemented `math/big` ordinary double-and-add scalar multiplication in `internal/reference`. Scalars are reduced modulo `r`; boundary inputs include 0, 1, `r-1`, and values adjacent to `r`. The generated point encodings are checked independently for canonical coordinates, curve membership, and `[r]P = O` before differential comparison. Infinity uses the canonical all-zero EIP-2537 encoding.

## Implementation comparisons

For each exact serialized multi-tuple input, record separately:

- Bor's source-faithful extracted `Run`: whether it returned an error, exact error, exact output bytes, and whether the output word equals 1.
- Direct gnark `PairingCheck`: operation error and identity result.
- Independent supranational/blst pairing aggregation: operation error and identity result.
- The mathematical scalar-product expectation, derived from the tuple scalars.

The critical false-acceptance condition is mathematical expectation `false` together with Bor `Run` returning no error and output `1`. Backend disagreements without that condition are classified separately and do not by themselves authorize Batch 6.

## Case families and reproducibility

The deterministic corpus uses an explicit seed recorded with its summary. It covers identity and nonidentity products, scalar cancellation, exponents 1 and `r-1`, tuple reordering and repetition, infinity mixed with ordinary points, scalar boundaries, and tuple counts 1, 2, 3, 8, 16, 32, 64, 127, 128, 129, plus larger practical batches. The exact input hex and all implementation outputs are stored in `differential-results.json`.

## Metamorphic self-consistency

The metamorphic pass uses algebraically equivalent serialized inputs to test each backend against its own outputs. It checks scalar transfer between G1 and G2, splitting one pairing term, distributing G1 addition, tuple permutation, appending a cancelling pair, appending an infinity pair, doubling a pair versus doubling one scalar, and an inverse-pair transform that must change a nonidentity result to identity. The expected relation (same or different output) follows from bilinearity and the scalar-product exponent. Bor, gnark, and blst are evaluated on both sides independently; the report does not infer correctness by majority vote or require cross-implementation agreement to establish each relation.

Exact metamorphic inputs and each implementation's two outputs are recorded in `metamorphic-results.json`.

Reproduction commands are recorded in `final-assessment.md` after integration. Dependencies remain pinned by the existing audit module; Bor production source is not modified and the full Bor repository is not cloned.
