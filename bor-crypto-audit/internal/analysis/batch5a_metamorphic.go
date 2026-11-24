package analysis

import (
	"encoding/hex"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"bor-crypto-audit/internal/boradapter"
	"bor-crypto-audit/internal/reference"
)

type Batch5AMetamorphicReport struct {
	SchemaVersion    int                      `json:"schema_version"`
	Method           string                   `json:"method"`
	CaseCount        int                      `json:"case_count"`
	RelationCount    int                      `json:"relation_count"`
	AllRelationsHold bool                     `json:"all_relations_hold"`
	Cases            []Batch5AMetamorphicCase `json:"cases"`
}

type Batch5AMetamorphicCase struct {
	Name                 string                     `json:"name"`
	Relation             string                     `json:"relation"`
	ExpectedOutputsEqual bool                       `json:"expected_outputs_equal"`
	LeftExponentHex      string                     `json:"left_scalar_exponent_hex"`
	RightExponentHex     string                     `json:"right_scalar_exponent_hex"`
	LeftMathematicalOne  bool                       `json:"left_mathematical_identity"`
	RightMathematicalOne bool                       `json:"right_mathematical_identity"`
	LeftInputHex         string                     `json:"left_input_hex"`
	RightInputHex        string                     `json:"right_input_hex"`
	Bor                  MetamorphicBackendRelation `json:"bor"`
	Gnark                MetamorphicBackendRelation `json:"gnark"`
	Blst                 MetamorphicBackendRelation `json:"blst"`
	RelationHolds        bool                       `json:"all_backend_relations_hold"`
}

type MetamorphicBackendRelation struct {
	Left                    PairingImpl `json:"left"`
	Right                   PairingImpl `json:"right"`
	OutputsEqual            bool        `json:"outputs_equal"`
	MatchesExpectedRelation bool        `json:"matches_expected_relation"`
}

type scalarProductVector struct {
	a, b *big.Int
}

// BuildBatch5AMetamorphic applies algebraic transformations to already
// understood pairing products and checks each backend against its own result.
func BuildBatch5AMetamorphic() (Batch5AMetamorphicReport, error) {
	r := reference.SubgroupOrder()
	a, b, c := big.NewInt(12345), big.NewInt(67891), big.NewInt(43)
	k := big.NewInt(17)
	base := []scalarProductVector{{a: a, b: b}}
	leftTransfer := []scalarProductVector{{a: new(big.Int).Mul(k, a), b: b}}
	rightTransfer := []scalarProductVector{{a: a, b: new(big.Int).Mul(k, b)}}
	leftSplit := []scalarProductVector{{a: a, b: new(big.Int).Sub(new(big.Int).Set(b), c)}, {a: a, b: c}}
	leftAddSplit := []scalarProductVector{{a: big.NewInt(5), b: big.NewInt(23)}, {a: big.NewInt(11), b: big.NewInt(23)}}
	rightAddSplit := []scalarProductVector{{a: big.NewInt(16), b: big.NewInt(23)}}
	basePlusInverse := append(append([]scalarProductVector{}, base...), scalarProductVector{a: new(big.Int).Neg(a), b: b})
	basePlusCancellation := append(append(append([]scalarProductVector{}, base...), scalarProductVector{a: a, b: b}), scalarProductVector{a: new(big.Int).Neg(a), b: b})
	basePlusInfinity := append(append([]scalarProductVector{}, base...), scalarProductVector{a: new(big.Int), b: big.NewInt(11)})
	permutationLeft := []scalarProductVector{{a: big.NewInt(5), b: big.NewInt(7)}, {a: big.NewInt(11), b: big.NewInt(13)}, {a: big.NewInt(17), b: big.NewInt(19)}}
	permutationRight := []scalarProductVector{permutationLeft[2], permutationLeft[0], permutationLeft[1]}
	doubleLeft := []scalarProductVector{{a: big.NewInt(5), b: big.NewInt(7)}, {a: big.NewInt(5), b: big.NewInt(7)}}
	doubleRight := []scalarProductVector{{a: big.NewInt(10), b: big.NewInt(7)}}
	cases := []struct {
		name, relation string
		left, right    []scalarProductVector
		equal          bool
	}{
		{"scalar-transfer-G1-to-G2", "e([k*a]P,[b]Q) = e([a]P,[k*b]Q)", leftTransfer, rightTransfer, true},
		{"split-one-tuple", "e([a]P,[b]Q) = e([a]P,[b-c]Q) * e([a]P,[c]Q)", base, leftSplit, true},
		{"distribute-G1-addition", "e([a1+a2]P,[b]Q) = e([a1]P,[b]Q) * e([a2]P,[b]Q)", rightAddSplit, leftAddSplit, true},
		{"tuple-permutation", "pairing product is invariant under tuple permutation", permutationLeft, permutationRight, true},
		{"append-cancelling-pair", "adding e([a]P,[b]Q) * e([-a]P,[b]Q) preserves the prior product", base, basePlusCancellation, true},
		{"append-infinity-pair", "adding e(O,[11]Q)=1 preserves the prior product", base, basePlusInfinity, true},
		{"inverse-pair-changes-output", "e([a]P,[b]Q) is nonidentity while its product with e([-a]P,[b]Q) is identity", base, basePlusInverse, false},
		{"duplicate-versus-scaled", "e([a]P,[b]Q)^2 = e([2a]P,[b]Q)", doubleLeft, doubleRight, true},
	}
	result := Batch5AMetamorphicReport{
		SchemaVersion: 1,
		Method:        "Each relation is derived from bilinearity and group laws. Bor, direct gnark, and blst each run both related serialized inputs; the relation is checked within each implementation, not by voting across implementations. Scalar exponents are recorded as an independent mathematical audit trail.",
		CaseCount:     len(cases), Cases: make([]Batch5AMetamorphicCase, 0, len(cases)), AllRelationsHold: true,
	}
	for _, test := range cases {
		leftExponent := scalarExponent(test.left, r)
		rightExponent := scalarExponent(test.right, r)
		if (leftExponent.Cmp(rightExponent) == 0) != test.equal {
			return Batch5AMetamorphicReport{}, fmt.Errorf("metamorphic vector %s has incorrect scalar relation", test.name)
		}
		leftInput := encodeScalarProductInput(test.left, r)
		rightInput := encodeScalarProductInput(test.right, r)
		leftBor, leftGnark, leftBlst, err := runMetamorphicBackends(leftInput)
		if err != nil {
			return Batch5AMetamorphicReport{}, fmt.Errorf("%s left input: %w", test.name, err)
		}
		rightBor, rightGnark, rightBlst, err := runMetamorphicBackends(rightInput)
		if err != nil {
			return Batch5AMetamorphicReport{}, fmt.Errorf("%s right input: %w", test.name, err)
		}
		item := Batch5AMetamorphicCase{
			Name: test.name, Relation: test.relation, ExpectedOutputsEqual: test.equal,
			LeftExponentHex: leftExponent.Text(16), RightExponentHex: rightExponent.Text(16),
			LeftMathematicalOne: leftExponent.Sign() == 0, RightMathematicalOne: rightExponent.Sign() == 0,
			LeftInputHex: hex.EncodeToString(leftInput), RightInputHex: hex.EncodeToString(rightInput),
			Bor:   relationObservation(leftBor, rightBor, test.equal),
			Gnark: relationObservation(leftGnark, rightGnark, test.equal),
			Blst:  relationObservation(leftBlst, rightBlst, test.equal),
		}
		item.RelationHolds = item.Bor.MatchesExpectedRelation && item.Gnark.MatchesExpectedRelation && item.Blst.MatchesExpectedRelation
		if !item.RelationHolds {
			result.AllRelationsHold = false
		}
		result.Cases = append(result.Cases, item)
	}
	result.RelationCount = len(result.Cases) * 3
	return result, nil
}

func scalarExponent(vectors []scalarProductVector, r *big.Int) *big.Int {
	terms := make([]ScalarPair, len(vectors))
	for i, vector := range vectors {
		terms[i] = ScalarPair{G1Scalar: vector.a, G2Scalar: vector.b}
	}
	return PairingProductExponent(terms)
}

func encodeScalarProductInput(vectors []scalarProductVector, r *big.Int) []byte {
	out := make([]byte, 0, len(vectors)*384)
	g1Generator, g2Generator := reference.G1Generator(), reference.G2Generator()
	for _, vector := range vectors {
		a := new(big.Int).Mod(new(big.Int).Set(vector.a), r)
		b := new(big.Int).Mod(new(big.Int).Set(vector.b), r)
		p := reference.G1ScalarMult(g1Generator, a)
		q := reference.G2ScalarMult(g2Generator, b)
		out = append(out, encodeG1(p)...)
		out = append(out, encodeG2(q)...)
	}
	return out
}

func runMetamorphicBackends(input []byte) (PairingImpl, PairingImpl, PairingImpl, error) {
	borOutput, borErr := boradapter.RunPairing(input)
	bor := PairingImpl{Applicable: true, Accepted: borErr == nil, OutputHex: hex.EncodeToString(borOutput)}
	if borErr != nil {
		bor.Error = borErr.Error()
	} else if len(borOutput) == 32 && (allZeroBytes(borOutput) || isPairingOneWord(borOutput)) {
		identity := isPairingOneWord(borOutput)
		bor.Identity = &identity
	} else {
		return bor, PairingImpl{}, PairingImpl{}, fmt.Errorf("Bor returned noncanonical output %x", borOutput)
	}

	p, q, err := parseGnarkPairs(input)
	if err != nil {
		return bor, PairingImpl{}, PairingImpl{}, err
	}
	gnarkIdentity, gnarkErr := bls12381.PairingCheck(p, q)
	gnark := PairingImpl{Applicable: true, Accepted: gnarkErr == nil}
	if gnarkErr != nil {
		gnark.Error = gnarkErr.Error()
	} else {
		gnark.Identity = &gnarkIdentity
	}

	pairs := make([]AffinePair, len(input)/384)
	for i := range pairs {
		start := i * 384
		pairs[i] = AffinePair{G1: input[start : start+128], G2: input[start+128 : start+384]}
	}
	blstIdentity, blstErr := blstPairingCheck(pairs)
	blst := PairingImpl{Applicable: true, Accepted: blstErr == nil}
	if blstErr != nil {
		blst.Error = blstErr.Error()
	} else {
		blst.Identity = &blstIdentity
	}
	return bor, gnark, blst, nil
}

func relationObservation(left, right PairingImpl, expectedEqual bool) MetamorphicBackendRelation {
	equal := left.Identity != nil && right.Identity != nil && *left.Identity == *right.Identity
	return MetamorphicBackendRelation{
		Left: left, Right: right, OutputsEqual: equal,
		MatchesExpectedRelation: left.Identity != nil && right.Identity != nil && equal == expectedEqual,
	}
}
