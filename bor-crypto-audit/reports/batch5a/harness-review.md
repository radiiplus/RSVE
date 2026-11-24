# Independent Harness Review

## Review status

Static review of the Batch 5A scalar oracle, corpus construction, and differential runner found no blocking methodological flaw. After integration, the final generated report was rechecked: all 91 cases and 5,032 tuples match the scalar oracle; Bor, gnark, and blst agree; no discrepancies or false acceptances were recorded. The complete test suite and module verification passed.

## Reviewed properties

- Mathematical expectation is recomputed as `sum(a_i*b_i) mod r` with `math/big`; neither gnark nor blst supplies the expected value.
- Generated point encodings are checked against independently recomputed `[a_i]G1` and `[b_i]G2`, then independently classified on-curve and in-subgroup. This ties serialized bytes to the scalar equation instead of trusting corpus labels alone.
- Bor `Run` error status, exact output bytes, output-word validity, and output-one status are separate fields. The critical condition is based on the full canonical 32-byte word `0...01` and mathematical exponent nonzero.
- Direct gnark and blst results are recorded independently from Bor's wrapper. blst uses a separate C/assembly implementation and the EIP-to-blst coordinate conversion already exercised by Batch 5 vectors.
- The canonical all-zero infinity encoding is treated as infinity by the corpus test. Removing a valid infinity pair from a blst product is mathematically sound because `e(O,Q)=e(P,O)=1`.
- Tuple order is explicitly reversed for identity cases; repeated pairs and mixed infinity cases are also generated. Production Run receives the exact concatenated encodings recorded by the report.

## Findings and caveats

- The first version of the random identity family used repeated positive/negative copies of one random term. The corpus implementation was revised to choose varied random scalar pairs and solve the final term for cancellation. A reusable deterministic scalar pool is a reasonable way to keep the independent `[r]P` classification cost bounded while retaining varied pair aggregation.
- The Batch 5A corpus is valid-point-only. `blstPairingCheck` elides a tuple if either point is infinity, which is equivalent for this scope. It would not serve as a general malformed-point validator when the other point in that tuple is invalid; malformed encodings are outside this batch's stated comparison domain.
- Batch 5A calls the extracted `Run` directly. It establishes pairing-product semantics and backend agreement for the tested vectors, not gas behavior or EVM execution. Economic conclusions still require the separate Batch 6 gate and actual Bor-compatible EVM execution if a false acceptance appears.
- Random scalar coverage is deterministic and reproducible, not exhaustive over all of `Fr`. Report the seed, scalar-pool strategy, tuple sizes, and exact serialized failing inputs if a discrepancy occurs.

## Recommendation

Keep `run_returned_no_error` distinct from `output_is_one` in all summaries. Treat an implementation-only mismatch as a separate potential consensus concern; classify it as a false pairing acceptance only when the independent scalar exponent is nonzero and Bor returns the exact output word `0...01` without error. Re-run the harness review against the final JSON after generation to ensure counts, case identities, and discrepancy classifications agree.
