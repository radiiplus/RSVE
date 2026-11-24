# BLS12-381 Pairing Precompile

Production source: Bor develop commit `cefbcfd4078e7a6cdb8e7642bc26e3589e05e7ab`, `core/vm/contracts.go`. The standalone adapter in `internal/boradapter/pairing.go` is generated from AST-selected source declarations by `tools/extract_pairing.go`; the extracted production function bodies are copied directly from the pinned source.

## Input and execution path

- Precompile address: `0x0f` (`PrecompiledContractsPrague`, production source line 141).
- Input must be nonempty and a multiple of 384 bytes: each tuple is 128 bytes of G1 followed by 256 bytes of G2 (`Run`, lines 1374-1384).
- G1 decoding reads 64-byte big-endian `x` and `y` field elements; G2 reads 64-byte `x.A0`, `x.A1`, `y.A0`, and `y.A1`. Each field element requires 16 zero prefix bytes. The pinned gnark-crypto `fp.BigEndian.Element` rejects values greater than or equal to the base-field modulus.
- `decodePointG1` and `decodePointG2` reject wrong point lengths, field-element decoding errors, and points failing `IsOnCurve` (lines 1435-1485).
- For each tuple, `Run` decodes G1, decodes G2, checks G1 subgroup membership, then checks G2 subgroup membership (lines 1394-1416).
- The decoded slices go to `bls12381.PairingCheck`; the output buffer is 32 bytes (lines 1418-1427).

## Return behavior

| Condition | Production return |
| --- | --- |
| Empty input or length not divisible by 384 | `nil, errBLS12381InvalidInputLength` at `Run` line 1384 |
| Malformed G1/G2 point, noncanonical field element, or off-curve point | `nil, error` propagated from the relevant decoder at `Run` lines 1399 or 1404; decode checks are at lines 1435-1485 |
| On-curve G1 outside the subgroup | `nil, errBLS12381G1PointSubgroup` at `Run` line 1411 |
| On-curve G2 outside the subgroup | `nil, errBLS12381G2PointSubgroup` at `Run` line 1414 |
| Subgroup-valid inputs, pairing product not identity (`ok == false`, `err == nil`) | 32 zero bytes, `nil` error |
| Subgroup-valid inputs, pairing product is identity (`ok == true`, `err == nil`) | 31 zero bytes followed by `0x01`, `nil` error |
| `PairingCheck` returns a non-nil error | 32 zero bytes, `nil` error; the production code does not propagate this error |

The last three cases follow the final branch: `out` starts zeroed, byte 31 is set only when `err == nil && ok`, and `Run` returns `out, nil` unconditionally after `PairingCheck` (lines 1421-1427). Error declarations are at lines 1119-1123.

The EIP-2537 G1/G2 addition precompiles are outside this pairing path. Their production comments explicitly state that subgroup checks are not needed for addition, as specified by EIP-2537; their behavior is not classified here as missing pairing validation.
