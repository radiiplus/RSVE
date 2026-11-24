# `go-bigmodexpfix` and Remaining `math/big` Paths

## Finding

The dependency name is not evidence that upstream Go `math/big` had a consensus bug. The pinned module describes itself as a copy of Go's package with additional `Int.Exp` optimizations. Its fork history shows bugs in those new exponentiation algorithms being fixed during development. That is evidence the custom implementation needed correction; it does not establish a defect in Go's standard library.

Both pinned Bor snapshots use `github.com/ethereum/go-bigmodexpfix v0.0.0-20250911101455-f9e208c548ab` (`f9e208c548ab3b256cb8d7ca2b72333ad656138d`). The source is a full copy of `math/big`, not a narrow modexp-only package, but `contracts.go` imports it under `patched_big` and uses it only for the modexp base, exponent, modulus, and result at `bigModExp.Run`.

## What the Fork Changes

The copied `nat.expNN` dispatches modular exponentiation by modulus shape and exponent size:

- Small exponents use square-and-multiply.
- Odd moduli use windowed Montgomery exponentiation.
- Power-of-two moduli use a specialized windowed exponentiation.
- Other even moduli use separate odd and power-of-two exponentiations and recombine them with the Chinese Remainder Theorem.

The fork's history records implementation defects in these additions. Commit `e2d20b4` is titled “Fix bug due to manual memory management”; its diff changes scratch-buffer sizing and copies a result out of stack-managed temporary storage before that storage is restored. Commit `c11dd59` adds stack restoration in the Montgomery path and changes its initialization. Commit `fd09008` adjusts precomputation scratch handling. These are fixes in the fork's custom optimization work, not evidence of a standard-library bug.

The pinned fork's `TestExponentiationAlgorithms` passed locally:

```sh
go mod download github.com/ethereum/go-bigmodexpfix@v0.0.0-20250911101455-f9e208c548ab
cd "$(go env GOPATH)/pkg/mod/github.com/ethereum/go-bigmodexpfix@v0.0.0-20250911101455-f9e208c548ab"
go test ./src/math/big -run '^TestExponentiationAlgorithms$' -count=1
```

That deterministic test compares the optimized algorithms to a slow square-and-multiply implementation across modulus sizes up to 384 bytes, exponent sizes up to 3,072 bits, odd, power-of-two, and mixed even moduli, and several base 2-adicities. It is useful implementation evidence, not an exhaustive proof or a comparison against every Go release.

## Bor Call-Path Split

In the pinned `core/vm/contracts.go`, `bigModExp.Run` still uses standard `math/big.Int` to parse the three 32-byte operand-length headers and read their `Uint64`/`BitLen` values. It uses `patched_big.Int` for the actual base/exponent/modulus values and the `Exp` operation. `RequiredGas` parses lengths with `uint256`, not `math/big`.

Standard `math/big` remains reachable in other production precompile paths in this same consensus-executed file:

- `ecrecover.Run` parses `r` and `s` with `math/big.Int` and passes them to signature validation and recovery.
- `runBn256ScalarMul` parses the scalar with `math/big.Int` and passes it to the BN256 implementation.
- `p256Verify.Run` parses signature and point coordinates with `math/big.Int` and passes them to verification.

The pinned `params/config.go` also uses standard `math/big` for chain fork heights, fork activation comparisons, chain IDs, and Bor fee calculations. Those values influence consensus rule selection and block processing. The source snapshot proves these call sites exist; this focused audit did not inventory every `math/big` use across the full Bor repository.

## Assessment

The proposed “patched modexp versus unpatched math/big” split is real at the package-call level, but it is not by itself a behavioral discrepancy: the standard-library call sites above perform different operations, while the modexp result is computed by the fork. No wrong result or consensus divergence was demonstrated here. The concrete next differential test, if this lead is pursued, is to compare the pinned fork's modular exponent result against an independent arbitrary-precision implementation across EIP-reachable input sizes and boundary cases, then verify the production `Run` output and gas path separately.
