package reference

import (
	"math/big"
	"strings"
	"testing"
)

func TestAuthoritativeParametersAndRepresentation(t *testing.T) {
	if BaseFieldModulus().Text(16) != baseFieldHex {
		t.Fatal("base-field modulus does not match EIP-2537")
	}
	if SubgroupOrder().Text(16) != orderHex {
		t.Fatal("subgroup order does not match EIP-2537")
	}
	if Fp2NonResidue().Text(16) != fp2NRHex || new(big.Int).Sub(BaseFieldModulus(), big.NewInt(1)).Cmp(Fp2NonResidue()) != 0 {
		t.Fatal("Fp2 non-residue is not p-1")
	}

	i := NewFp2(big.NewInt(0), big.NewInt(1))
	if got := fp2Mul(i, i); got.C0.Cmp(fpNeg(big.NewInt(1))) != 0 || got.C1.Sign() != 0 {
		t.Fatal("Fp2 basis element does not square to -1")
	}
}

func TestStandardGeneratorsAndSubgroupOrder(t *testing.T) {
	g1 := G1Generator()
	if !G1OnCurve(g1) {
		t.Fatal("standard G1 generator is not on the G1 curve")
	}
	if !G1InSubgroup(g1) {
		t.Fatal("[r]G1 generator is not infinity")
	}
	if !G1Equal(G1ScalarMult(g1, big.NewInt(1)), g1) {
		t.Fatal("[1]G1 generator differs from the standard generator")
	}
	if !G1ScalarMult(g1, big.NewInt(0)).Infinity {
		t.Fatal("[0]G1 generator is not infinity")
	}
	if !G1Add(g1, G1Neg(g1)).Infinity {
		t.Fatal("G1 generator plus its inverse is not infinity")
	}

	g2 := G2Generator()
	if !G2OnCurve(g2) {
		t.Fatal("standard G2 generator is not on the G2 twist")
	}
	if !G2InSubgroup(g2) {
		t.Fatal("[r]G2 generator is not infinity")
	}
	if !G2Equal(G2ScalarMult(g2, big.NewInt(1)), g2) {
		t.Fatal("[1]G2 generator differs from the standard generator")
	}
	if !G2ScalarMult(g2, big.NewInt(0)).Infinity {
		t.Fatal("[0]G2 generator is not infinity")
	}
	if !G2Add(g2, G2Neg(g2)).Infinity {
		t.Fatal("G2 generator plus its inverse is not infinity")
	}

	if g2.X.C0.Cmp(mustHex(g2GeneratorX0Hex)) != 0 || g2.X.C1.Cmp(mustHex(g2GeneratorX1Hex)) != 0 || g2.Y.C0.Cmp(mustHex(g2GeneratorY0Hex)) != 0 || g2.Y.C1.Cmp(mustHex(g2GeneratorY1Hex)) != 0 {
		t.Fatal("G2 generator coefficients are not in EIP-2537 c0, c1 order")
	}
}

func TestDoubleAndAddAgainstEIP2537Vectors(t *testing.T) {
	g1 := G1Generator()
	wantG1 := parseG1Vector(t, "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28")
	if got := G1ScalarMult(g1, big.NewInt(2)); !G1Equal(got, wantG1) {
		t.Fatalf("[2]G1 mismatch: got (%s, %s)", got.X.Text(16), got.Y.Text(16))
	}
	if !G1Equal(G1Add(g1, g1), wantG1) {
		t.Fatal("G1 addition disagrees with the EIP-2537 double vector")
	}

	g2 := G2Generator()
	wantG2 := parseG2Vector(t, "000000000000000000000000000000001638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053000000000000000000000000000000000a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577000000000000000000000000000000000468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899000000000000000000000000000000000f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3")
	if got := G2ScalarMult(g2, big.NewInt(2)); !G2Equal(got, wantG2) {
		t.Fatalf("[2]G2 mismatch: got X=(%s,%s) Y=(%s,%s)", got.X.C0.Text(16), got.X.C1.Text(16), got.Y.C0.Text(16), got.Y.C1.Text(16))
	}
	if !G2Equal(G2Add(g2, g2), wantG2) {
		t.Fatal("G2 addition disagrees with the EIP-2537 double vector")
	}
}

func TestFiniteFieldArithmetic(t *testing.T) {
	if fpAdd(pModulus, big.NewInt(2)).Cmp(big.NewInt(2)) != 0 {
		t.Fatal("Fp addition did not reduce modulo p")
	}
	if fpMul(big.NewInt(3), fpInv(big.NewInt(3))).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("Fp inverse is incorrect")
	}
	a := NewFp2(big.NewInt(3), big.NewInt(5))
	if !fp2Equal(fp2Mul(a, fp2Inv(a)), fp2FromUint64(1)) {
		t.Fatal("Fp2 inverse is incorrect")
	}
}

func parseG1Vector(t *testing.T, encoded string) G1Point {
	t.Helper()
	if len(encoded) != 256 {
		t.Fatalf("bad G1 vector width: %d", len(encoded))
	}
	return G1Point{X: mustHex(encoded[:128]), Y: mustHex(encoded[128:])}
}

func parseG2Vector(t *testing.T, encoded string) G2Point {
	t.Helper()
	if len(encoded) != 512 {
		t.Fatalf("bad G2 vector width: %d", len(encoded))
	}
	parts := make([]*big.Int, 4)
	for i := range parts {
		parts[i] = mustHex(encoded[i*128 : (i+1)*128])
	}
	return G2Point{
		X: NewFp2(parts[0], parts[1]),
		Y: NewFp2(parts[2], parts[3]),
	}
}

func TestGeneratorHexConstantsAreCanonical(t *testing.T) {
	for _, value := range []string{g1GeneratorXHex, g1GeneratorYHex, g2GeneratorX0Hex, g2GeneratorX1Hex, g2GeneratorY0Hex, g2GeneratorY1Hex} {
		if strings.ToLower(value) != value || len(value) != 96 || mustHex(value).Cmp(pModulus) >= 0 {
			t.Fatalf("noncanonical generator coordinate %q", value)
		}
	}
}
