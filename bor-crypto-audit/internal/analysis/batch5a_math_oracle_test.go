package analysis

import (
	"math/big"
	"testing"

	"bor-crypto-audit/internal/reference"
)

func TestPairingProductScalarOracle(t *testing.T) {
	r := reference.SubgroupOrder()
	rMinusOne := new(big.Int).Sub(new(big.Int).Set(r), big.NewInt(1))
	cases := []struct {
		name  string
		pairs []ScalarPair
		want  string
	}{
		{name: "empty product", want: "0"},
		{name: "zero scalar", pairs: []ScalarPair{{G1Scalar: big.NewInt(0), G2Scalar: big.NewInt(7)}}, want: "0"},
		{name: "nonidentity exponent", pairs: []ScalarPair{{G1Scalar: big.NewInt(3), G2Scalar: big.NewInt(4)}}, want: "c"},
		{name: "exact cancellation", pairs: []ScalarPair{{G1Scalar: big.NewInt(1), G2Scalar: big.NewInt(1)}, {G1Scalar: big.NewInt(2), G2Scalar: big.NewInt(1)}, {G1Scalar: new(big.Int).Neg(big.NewInt(3)), G2Scalar: big.NewInt(1)}}, want: "0"},
		{name: "near identity positive", pairs: []ScalarPair{{G1Scalar: big.NewInt(1), G2Scalar: big.NewInt(1)}, {G1Scalar: rMinusOne, G2Scalar: big.NewInt(1)}}, want: "0"},
		{name: "exponent one", pairs: []ScalarPair{{G1Scalar: big.NewInt(1), G2Scalar: big.NewInt(1)}}, want: "1"},
		{name: "exponent r minus one", pairs: []ScalarPair{{G1Scalar: rMinusOne, G2Scalar: big.NewInt(1)}}, want: rMinusOne.Text(16)},
		{name: "scalar r reduces to zero", pairs: []ScalarPair{{G1Scalar: r, G2Scalar: big.NewInt(1)}}, want: "0"},
		{name: "scalar r plus one reduces to one", pairs: []ScalarPair{{G1Scalar: new(big.Int).Add(new(big.Int).Set(r), big.NewInt(1)), G2Scalar: big.NewInt(1)}}, want: "1"},
		{name: "negative scalar reduces modulo r", pairs: []ScalarPair{{G1Scalar: big.NewInt(-1), G2Scalar: big.NewInt(1)}}, want: rMinusOne.Text(16)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PairingProductExponent(tc.pairs)
			if got.Text(16) != tc.want {
				t.Fatalf("exponent = %s, want %s", got.Text(16), tc.want)
			}
			wantIdentity, ok := new(big.Int).SetString(tc.want, 16)
			if !ok {
				t.Fatalf("invalid expected exponent %q", tc.want)
			}
			if PairingProductIsIdentity(tc.pairs) != (wantIdentity.Sign() == 0) {
				t.Fatal("identity predicate disagrees with exponent")
			}
		})
	}
}

func TestBoundaryScalarPointsRemainInReferenceGroups(t *testing.T) {
	r := reference.SubgroupOrder()
	scalars := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(new(big.Int).Set(r), big.NewInt(1)),
		new(big.Int).Set(r),
		new(big.Int).Add(new(big.Int).Set(r), big.NewInt(1)),
	}
	g1 := reference.G1Generator()
	g2 := reference.G2Generator()
	for _, scalar := range scalars {
		p := reference.G1ScalarMult(g1, scalar)
		q := reference.G2ScalarMult(g2, scalar)
		if !reference.G1OnCurve(p) || !reference.G1InSubgroup(p) {
			t.Errorf("[scalar]G1 is not in the reference group for scalar %s", scalar.Text(16))
		}
		if !reference.G2OnCurve(q) || !reference.G2InSubgroup(q) {
			t.Errorf("[scalar]G2 is not in the reference group for scalar %s", scalar.Text(16))
		}
	}
	if !reference.G1ScalarMult(g1, r).Infinity || !reference.G2ScalarMult(g2, r).Infinity {
		t.Fatal("[r] standard generator did not produce infinity")
	}
	if !reference.G1Add(reference.G1ScalarMult(g1, new(big.Int).Sub(new(big.Int).Set(r), big.NewInt(1))), g1).Infinity {
		t.Fatal("[r-1]G1 + G1 did not produce infinity")
	}
	if !reference.G2Add(reference.G2ScalarMult(g2, new(big.Int).Sub(new(big.Int).Set(r), big.NewInt(1))), g2).Infinity {
		t.Fatal("[r-1]G2 + G2 did not produce infinity")
	}
}
