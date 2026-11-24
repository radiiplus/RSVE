# Independent BLS12-381 Mathematical Oracle

Implementation: `internal/reference/oracle.go`. It uses `math/big` for all field and point arithmetic. The package does not import gnark-crypto and does not call optimized subgroup predicates, endomorphisms, or library point multiplication.

## Parameters and representation

The parameters and generator coordinates below are from [EIP-2537, Curve parameters and Fields and Groups](https://eips.ethereum.org/EIPS/eip-2537#curve-parameters):

- Base-field modulus `p`: `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`.
- Subgroup order `r`: `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
- G1 curve: `y^2 = x^3 + 4` over `Fp`.
- Fp2: coefficients are `(c0,c1)` representing `c0 + c1*i`, with `i^2 = -1`; the EIP non-residue is `p - 1`.
- G2 twist: `y^2 = x^3 + 4*(1+i)`, so its Fp2 curve coefficient is `(4,4)`.
- The G2 generator and encoded coordinates use `x.c0, x.c1, y.c0, y.c1` order. This matches the EIP's `encode(c0) || encode(c1)` rule and Bor's decoder assignment to `E2{A0: x0, A1: x1}`.

## Arithmetic and membership

Fp operations reduce `math/big` integers modulo `p`. Fp2 multiplication is `(a0+a1*i)(b0+b1*i) = (a0*b0-a1*b1) + (a0*b1+a1*b0)*i`. Affine point addition uses the ordinary slope formulas over Fp or Fp2. Scalar multiplication is bitwise double-and-add; it performs no endomorphism or library multiplication. `G1InSubgroup(P)` and `G2InSubgroup(P)` return whether the corresponding ordinary scalar multiplication `[r]P` is the point at infinity.

## Validation

`internal/reference/oracle_test.go` validates the exact parameter constants and Fp2 basis relation, checks the standard EIP generators are on their curves and that `[r]G1 = [r]G2 = O`, and checks identity, inverse, and scalar-zero/one behavior. It also compares the oracle's `[2]G1` and `[2]G2` results against the published [EIP-2537 G1 multiplication vectors](https://eips.ethereum.org/assets/eip-2537/mul_G1_bls.json) and [G2 multiplication vectors](https://eips.ethereum.org/assets/eip-2537/mul_G2_bls.json).

Validation command: `go test ./internal/reference`.
