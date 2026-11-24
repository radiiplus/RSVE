package analysis

import (
	"encoding/hex"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	blst "github.com/supranational/blst/bindings/go"

	"bor-crypto-audit/internal/boradapter"
	"bor-crypto-audit/internal/reference"
)

type PairingDifferentialReport struct {
	SchemaVersion  int                   `json:"schema_version"`
	BorCommit      string                `json:"bor_commit"`
	GnarkVersion   string                `json:"gnark_crypto_version"`
	Independent    IndependentInfo       `json:"independent_pairing_implementation"`
	Batch4Followup OffSubgroupFollowup   `json:"batch4_off_subgroup_followup"`
	Cases          []PairingDifferential `json:"cases"`
}

type IndependentInfo struct {
	Name                    string `json:"name"`
	Version                 string `json:"version"`
	Method                  string `json:"method"`
	DifferentImplementation bool   `json:"different_implementation_from_gnark"`
}

type OffSubgroupFollowup struct {
	Batch4Findings int                `json:"batch4_findings"`
	AcceptedCount  int                `json:"bor_accepted_off_subgroup_count"`
	Cases          []OffSubgroupProbe `json:"cases"`
	Conclusion     string             `json:"conclusion"`
}

type OffSubgroupProbe struct {
	Name                     string `json:"name"`
	Curve                    string `json:"curve"`
	ReferenceOnCurve         bool   `json:"reference_on_curve"`
	ReferenceInSubgroup      bool   `json:"reference_in_subgroup"`
	BorDecoderAccepted       bool   `json:"bor_decoder_accepted"`
	BorPairingAccepted       bool   `json:"bor_pairing_accepted"`
	BorPairingError          string `json:"bor_pairing_error,omitempty"`
	ExactPairingInputHex     string `json:"exact_pairing_input_hex"`
	IndependentPairingTested bool   `json:"independent_pairing_tested"`
	GnarkPairingIdentity     *bool  `json:"gnark_pairing_identity,omitempty"`
	BlstPairingIdentity      *bool  `json:"blst_pairing_identity,omitempty"`
	ReasonNotTested          string `json:"reason_not_tested,omitempty"`
}

type PairingDifferential struct {
	Name                 string      `json:"name"`
	Category             string      `json:"category"`
	TupleCount           int         `json:"tuple_count"`
	InputLength          int         `json:"input_length"`
	InputHex             string      `json:"input_hex"`
	MathematicalExpected *bool       `json:"mathematical_expected_identity,omitempty"`
	MathematicalBasis    string      `json:"mathematical_basis"`
	BorRun               PairingImpl `json:"bor_run"`
	GnarkDirect          PairingImpl `json:"gnark_pairing_check"`
	BlstDirect           PairingImpl `json:"blst_pairing_check"`
	ImplementationsAgree *bool       `json:"implementations_agree,omitempty"`
	MatchesMathematics   *bool       `json:"all_match_mathematics,omitempty"`
}

type PairingImpl struct {
	Applicable bool   `json:"applicable"`
	Accepted   bool   `json:"accepted"`
	Error      string `json:"error,omitempty"`
	Identity   *bool  `json:"identity,omitempty"`
	OutputHex  string `json:"output_hex,omitempty"`
}

func BuildPairingDifferential(batch4 Report) (PairingDifferentialReport, error) {
	g1 := reference.G1Generator()
	g2 := reference.G2Generator()
	q := encodeG2(g2)
	p := encodeG1(g1)
	minusP := encodeG1(reference.G1Neg(g1))
	minusQ := encodeG2(reference.G2Neg(g2))
	twoP := encodeG1(reference.G1ScalarMult(g1, big.NewInt(2)))
	minusThreeP := encodeG1(reference.G1Neg(reference.G1ScalarMult(g1, big.NewInt(3))))
	zero := make([]byte, 128)
	zeroG2 := make([]byte, 256)

	cases := []pairingVector{
		{name: "generator-pair-non-identity", category: "known-non-identity", pairs: []AffinePair{{G1: p, G2: q}}, expected: boolPtr(false), basis: "EIP-2537 requires non-degeneracy; standard generators pair to a non-identity element"},
		{name: "generator-and-negative-g1-identity", category: "inverse-cancellation", pairs: []AffinePair{{G1: p, G2: q}, {G1: minusP, G2: q}}, expected: boolPtr(true), basis: "bilinearity: e(P,Q) * e(-P,Q) = e(P + (-P),Q) = 1"},
		{name: "generator-and-negative-g2-identity", category: "inverse-cancellation", pairs: []AffinePair{{G1: p, G2: q}, {G1: p, G2: minusQ}}, expected: boolPtr(true), basis: "bilinearity: e(P,Q) * e(P,-Q) = e(P,Q + (-Q)) = 1"},
		{name: "three-tuple-scalar-cancellation", category: "multiple-tuples", pairs: []AffinePair{{G1: p, G2: q}, {G1: twoP, G2: q}, {G1: minusThreeP, G2: q}}, expected: boolPtr(true), basis: "bilinearity: e(G,Q) * e(2G,Q) * e(-3G,Q) = 1"},
		{name: "g1-infinity-pair", category: "infinity", pairs: []AffinePair{{G1: zero, G2: q}}, expected: boolPtr(true), basis: "e(O,Q) = 1"},
		{name: "g2-infinity-pair", category: "infinity", pairs: []AffinePair{{G1: p, G2: zeroG2}}, expected: boolPtr(true), basis: "e(P,O) = 1"},
		{name: "both-infinity-pair", category: "infinity", pairs: []AffinePair{{G1: zero, G2: zeroG2}}, expected: boolPtr(true), basis: "e(O,O) = 1"},
		{name: "infinity-plus-generator-pair", category: "multiple-tuples", pairs: []AffinePair{{G1: zero, G2: q}, {G1: p, G2: q}}, expected: boolPtr(false), basis: "identity tuple contributes 1; remaining standard generator pairing is non-identity"},
	}
	for _, count := range []int{1, 2, 3, 127, 128, 129} {
		pairs := repeatedPair(p, q, count)
		cases = append(cases, pairingVector{
			name: fmt.Sprintf("generator-pair-batch-%d", count), category: "boundary-sized-batch", pairs: pairs,
			expected: boolPtr(false), basis: fmt.Sprintf("e(G,Q)^%d is non-identity because the generator pairing has prime order r and %d is not divisible by r", count, count),
		})
	}

	for _, length := range []int{0, 383, 385, 767, 769} {
		input := make([]byte, length)
		cases = append(cases, pairingVector{
			name: fmt.Sprintf("invalid-input-length-%d", length), category: "input-length-boundary", rawInput: input,
			basis: "EIP-2537 pairing input must be a positive multiple of 384 bytes; no mathematical pairing is defined for this malformed encoding",
		})
	}

	results := make([]PairingDifferential, 0, len(cases))
	for _, vector := range cases {
		input := vector.rawInput
		if input == nil {
			input = encodePairs(vector.pairs)
		}
		results = append(results, comparePairingVector(vector, input))
	}

	followup := offSubgroupFollowup(batch4)
	return PairingDifferentialReport{
		SchemaVersion: 1,
		BorCommit:     "cefbcfd4078e7a6cdb8e7642bc26e3589e05e7ab",
		GnarkVersion:  "v0.19.2",
		Independent: IndependentInfo{
			Name: "supranational/blst", Version: "v0.3.17",
			Method:                  "C/assembly blst PairingRawAggregate + PairingFinalVerify; EIP affine encodings are converted to blst's uncompressed serialization; EIP infinity pairs are removed using e(O,Q)=e(P,O)=1",
			DifferentImplementation: true,
		},
		Batch4Followup: followup,
		Cases:          results,
	}, nil
}

type pairingVector struct {
	name     string
	category string
	pairs    []AffinePair
	rawInput []byte
	expected *bool
	basis    string
}

func comparePairingVector(vector pairingVector, input []byte) PairingDifferential {
	borOutput, borErr := boradapter.RunPairing(input)
	bor := PairingImpl{Applicable: true, Accepted: borErr == nil, OutputHex: hex.EncodeToString(borOutput)}
	if borErr != nil {
		bor.Error = borErr.Error()
	}
	if borErr == nil && len(borOutput) == 32 {
		identity := borOutput[31] == 1
		bor.Identity = &identity
	}

	gnark := PairingImpl{}
	blstResult := PairingImpl{}
	wellFormed := len(input) > 0 && len(input)%384 == 0
	var parseErr error
	var p []bls12381.G1Affine
	var q []bls12381.G2Affine
	if wellFormed {
		p, q, parseErr = parseGnarkPairs(input)
	}
	if parseErr != nil {
		wellFormed = false
		gnark.Error = parseErr.Error()
	}
	if wellFormed {
		value, err := bls12381.PairingCheck(p, q)
		gnark.Applicable = true
		gnark.Accepted = err == nil
		if err != nil {
			gnark.Error = err.Error()
		} else {
			gnarkValue := value
			gnark.Identity = &gnarkValue
		}
		blstValue, err := blstPairingCheck(vector.pairs)
		blstResult.Applicable = true
		blstResult.Accepted = err == nil
		if err != nil {
			blstResult.Error = err.Error()
		} else {
			blstResult.Identity = &blstValue
		}
	} else if len(input) > 0 && len(input)%384 == 0 {
		gnark.Applicable = true
		gnark.Error = "input coordinates could not be parsed"
		blstResult.Applicable = true
		blstResult.Error = "input coordinates could not be parsed"
	}

	var agree, matches bool
	var agreePtr, matchesPtr *bool
	if gnark.Identity != nil && blstResult.Identity != nil && bor.Identity != nil {
		agree = *gnark.Identity == *blstResult.Identity && *gnark.Identity == *bor.Identity
		agreePtr = &agree
		if vector.expected != nil {
			matches = *gnark.Identity == *vector.expected && *blstResult.Identity == *vector.expected && *bor.Identity == *vector.expected
			matchesPtr = &matches
		}
	}
	return PairingDifferential{
		Name: vector.name, Category: vector.category,
		TupleCount: len(input) / 384, InputLength: len(input), InputHex: hex.EncodeToString(input),
		MathematicalExpected: vector.expected, MathematicalBasis: vector.basis,
		BorRun: bor, GnarkDirect: gnark, BlstDirect: blstResult,
		ImplementationsAgree: agreePtr, MatchesMathematics: matchesPtr,
	}
}

func parseGnarkPairs(input []byte) ([]bls12381.G1Affine, []bls12381.G2Affine, error) {
	pairs := len(input) / 384
	g1s := make([]bls12381.G1Affine, pairs)
	g2s := make([]bls12381.G2Affine, pairs)
	for i := 0; i < pairs; i++ {
		off := i * 384
		g1, err := parseGnarkG1(input[off : off+128])
		if err != nil {
			return nil, nil, fmt.Errorf("tuple %d G1: %w", i, err)
		}
		g2, err := parseGnarkG2(input[off+128 : off+384])
		if err != nil {
			return nil, nil, fmt.Errorf("tuple %d G2: %w", i, err)
		}
		g1s[i], g2s[i] = g1, g2
	}
	return g1s, g2s, nil
}

func parseGnarkG1(encoded []byte) (bls12381.G1Affine, error) {
	if len(encoded) != 128 {
		return bls12381.G1Affine{}, fmt.Errorf("invalid G1 width")
	}
	x, err := parseGnarkField(encoded[:64])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	y, err := parseGnarkField(encoded[64:])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	return bls12381.G1Affine{X: x, Y: y}, nil
}

func parseGnarkG2(encoded []byte) (bls12381.G2Affine, error) {
	if len(encoded) != 256 {
		return bls12381.G2Affine{}, fmt.Errorf("invalid G2 width")
	}
	x0, err := parseGnarkField(encoded[:64])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	x1, err := parseGnarkField(encoded[64:128])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	y0, err := parseGnarkField(encoded[128:192])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	y1, err := parseGnarkField(encoded[192:])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	return bls12381.G2Affine{X: bls12381.E2{A0: x0, A1: x1}, Y: bls12381.E2{A0: y0, A1: y1}}, nil
}

func parseGnarkField(encoded []byte) (fp.Element, error) {
	if len(encoded) != 64 {
		return fp.Element{}, fmt.Errorf("invalid Fp width")
	}
	for _, b := range encoded[:16] {
		if b != 0 {
			return fp.Element{}, fmt.Errorf("nonzero high bytes")
		}
	}
	var raw [fp.Bytes]byte
	copy(raw[:], encoded[16:])
	return fp.BigEndian.Element(&raw)
}

func encodePairs(pairs []AffinePair) []byte {
	out := make([]byte, 0, len(pairs)*384)
	for _, pair := range pairs {
		out = append(out, pair.G1...)
		out = append(out, pair.G2...)
	}
	return out
}

func repeatedPair(p, q []byte, count int) []AffinePair {
	pairs := make([]AffinePair, count)
	for i := range pairs {
		pairs[i] = AffinePair{G1: p, G2: q}
	}
	return pairs
}

func offSubgroupFollowup(batch4 Report) OffSubgroupFollowup {
	followup := OffSubgroupFollowup{Batch4Findings: len(batch4.Findings)}
	for _, result := range batch4.Cases {
		if result.Reference.Label != "on-curve-outside-subgroup" {
			continue
		}
		probe := OffSubgroupProbe{
			Name: result.Name, Curve: result.PointUnderTestCurve,
			ReferenceOnCurve:     boolValue(result.Reference.OnCurve),
			ReferenceInSubgroup:  boolValue(result.Reference.InSubgroup),
			BorDecoderAccepted:   result.BorDecoder.DecoderAccepted,
			BorPairingAccepted:   result.Pairing.Accepted,
			BorPairingError:      result.Pairing.Error,
			ExactPairingInputHex: result.Pairing.InputHex,
		}
		if result.Pairing.Accepted {
			followup.AcceptedCount++
			input := decodeHex(result.Pairing.InputHex)
			pairs, err := parseAffinePairs(input)
			if err == nil {
				gnarkPairsP, gnarkPairsQ, err := parseGnarkPairs(input)
				if err == nil {
					identity, gnarkErr := bls12381.PairingCheck(gnarkPairsP, gnarkPairsQ)
					if gnarkErr == nil {
						probe.GnarkPairingIdentity = &identity
					}
					identity, blstErr := blstPairingCheckRaw(pairs)
					if blstErr == nil {
						probe.BlstPairingIdentity = &identity
					}
					probe.IndependentPairingTested = blstErr == nil
				}
			}
		} else {
			probe.ReasonNotTested = "Batch 4 Bor pairing Run rejected this point before pairing; no accepted off-subgroup input exists to test conditionally"
		}
		followup.Cases = append(followup.Cases, probe)
	}
	if followup.AcceptedCount == 0 {
		followup.Conclusion = "Batch 4 produced no Bor-accepted off-subgroup input; the conditional false-acceptance question has no input instance in this corpus"
	} else {
		followup.Conclusion = "At least one off-subgroup input was accepted in Batch 4; its exact pairing tuple is cross-checked with gnark and blst above"
	}
	return followup
}

func parseAffinePairs(input []byte) ([]AffinePair, error) {
	if len(input) == 0 || len(input)%384 != 0 {
		return nil, fmt.Errorf("input is not a nonempty sequence of 384-byte tuples")
	}
	pairs := make([]AffinePair, len(input)/384)
	for i := range pairs {
		off := i * 384
		pairs[i] = AffinePair{G1: input[off : off+128], G2: input[off+128 : off+384]}
	}
	return pairs, nil
}

func blstPairingCheckRaw(pairs []AffinePair) (bool, error) {
	ctx := blst.PairingCtx(false, nil)
	added := 0
	for i, pair := range pairs {
		if allZeroBytes(pair.G1) || allZeroBytes(pair.G2) {
			continue
		}
		p, err := parseBlstG1(pair.G1)
		if err != nil {
			return false, fmt.Errorf("pair %d G1: %w", i, err)
		}
		q, err := parseBlstG2(pair.G2)
		if err != nil {
			return false, fmt.Errorf("pair %d G2: %w", i, err)
		}
		blst.PairingRawAggregate(ctx, q, p)
		added++
	}
	if added == 0 {
		return true, nil
	}
	blst.PairingCommit(ctx)
	return blst.PairingFinalVerify(ctx), nil
}
