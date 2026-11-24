package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"bor-crypto-audit/internal/boradapter"
	"bor-crypto-audit/internal/corpus"
	"bor-crypto-audit/internal/reference"
)

type Batch5ADifferentialReport struct {
	SchemaVersion            int                       `json:"schema_version"`
	Seed                     string                    `json:"seed"`
	BorCommit                string                    `json:"bor_commit"`
	GnarkCryptoVersion       string                    `json:"gnark_crypto_version"`
	BlstVersion              string                    `json:"blst_version"`
	MathematicalMethod       string                    `json:"mathematical_method"`
	CaseCount                int                       `json:"case_count"`
	TupleCount               int                       `json:"tuple_count"`
	BorRunErrorCount         int                       `json:"bor_run_error_count"`
	FalseAcceptanceCount     int                       `json:"false_acceptance_count"`
	BackendDisagreementCount int                       `json:"backend_disagreement_count"`
	Cases                    []Batch5ADifferentialCase `json:"cases"`
	Discrepancies            []Batch5ADiscrepancy      `json:"discrepancies"`
}

type Batch5ADifferentialCase struct {
	Name                   string               `json:"name"`
	Category               string               `json:"category"`
	TupleCount             int                  `json:"tuple_count"`
	InputLength            int                  `json:"input_length"`
	InputSHA256            string               `json:"input_sha256"`
	InputHex               string               `json:"input_hex"`
	MathematicalExponent   string               `json:"mathematical_exponent_hex"`
	MathematicalIdentity   bool                 `json:"mathematical_identity"`
	CorpusExpectedIdentity bool                 `json:"corpus_expected_identity"`
	CorpusExpectedExponent string               `json:"corpus_expected_exponent_hex"`
	ExpectedMatchesCorpus  bool                 `json:"oracle_matches_corpus_expectation"`
	Bor                    Batch5ABorResult     `json:"bor_production_run"`
	Gnark                  Batch5ABackendResult `json:"gnark_pairing_check"`
	Blst                   Batch5ABackendResult `json:"blst_pairing_check"`
	ImplementationsAgree   *bool                `json:"implementations_agree,omitempty"`
	AllMatchMathematics    bool                 `json:"all_match_mathematics"`
}

type Batch5ABorResult struct {
	RunReturnedNoError bool   `json:"run_returned_no_error"`
	Error              string `json:"error,omitempty"`
	OutputHex          string `json:"output_hex"`
	OutputLength       int    `json:"output_length"`
	OutputWordValid    bool   `json:"output_word_valid"`
	OutputIsOne        *bool  `json:"output_is_one,omitempty"`
}

type Batch5ABackendResult struct {
	Applicable bool   `json:"applicable"`
	Error      string `json:"error,omitempty"`
	Identity   *bool  `json:"identity,omitempty"`
}

type Batch5ADiscrepancy struct {
	CaseName             string `json:"case_name"`
	Class                string `json:"class"`
	MathematicalExponent string `json:"mathematical_exponent_hex"`
	MathematicalIdentity bool   `json:"mathematical_identity"`
	InputHex             string `json:"input_hex"`
	BorOutputHex         string `json:"bor_output_hex"`
	BorError             string `json:"bor_error,omitempty"`
	GnarkIdentity        *bool  `json:"gnark_identity,omitempty"`
	GnarkError           string `json:"gnark_error,omitempty"`
	BlstIdentity         *bool  `json:"blst_identity,omitempty"`
	BlstError            string `json:"blst_error,omitempty"`
}

// CompareBatch5ACorpus runs every generated scalar-pair case through Bor's
// source-faithful Run, direct gnark PairingCheck, and the independent blst
// implementation. Expected identity is recomputed from scalar coefficients.
func CompareBatch5ACorpus(doc corpus.Batch5ACorpus) (Batch5ADifferentialReport, error) {
	report := Batch5ADifferentialReport{
		SchemaVersion:      1,
		Seed:               doc.Seed,
		BorCommit:          "cefbcfd4078e7a6cdb8e7642bc26e3589e05e7ab",
		GnarkCryptoVersion: "v0.19.2",
		BlstVersion:        "v0.3.17",
		MathematicalMethod: "bilinearity: for P_i=[a_i]G1 and Q_i=[b_i]G2, product_i e(P_i,Q_i)=e(G1,G2)^(sum_i a_i*b_i); since e(G1,G2) has prime order r, identity iff sum_i a_i*b_i = 0 mod r. Scalars and reference points are from independent math/big code; expected results do not use gnark or blst.",
		CaseCount:          len(doc.Cases),
		Cases:              make([]Batch5ADifferentialCase, 0, len(doc.Cases)),
	}
	pointCache := batch5AVerificationCache{g1: make(map[string][]byte), g2: make(map[string][]byte)}
	for _, testCase := range doc.Cases {
		comparison, scalarExponent, err := compareBatch5ACase(testCase, &pointCache)
		if err != nil {
			return Batch5ADifferentialReport{}, fmt.Errorf("case %s: %w", testCase.Name, err)
		}
		report.TupleCount += comparison.TupleCount
		if !comparison.Bor.RunReturnedNoError {
			report.BorRunErrorCount++
		}
		if !scalarExponent && comparison.Bor.RunReturnedNoError && boolValue(comparison.Bor.OutputIsOne) {
			report.FalseAcceptanceCount++
		}
		if comparison.ImplementationsAgree != nil && !*comparison.ImplementationsAgree {
			report.BackendDisagreementCount++
		}
		report.Cases = append(report.Cases, comparison)
		if !comparison.AllMatchMathematics || comparison.Bor.OutputIsOne == nil || !comparison.Bor.RunReturnedNoError || comparison.Gnark.Error != "" || comparison.Blst.Error != "" || comparison.ImplementationsAgree == nil || !*comparison.ImplementationsAgree {
			report.Discrepancies = append(report.Discrepancies, Batch5ADiscrepancy{
				CaseName: comparison.Name, Class: discrepancyClass(comparison),
				MathematicalExponent: comparison.MathematicalExponent,
				MathematicalIdentity: comparison.MathematicalIdentity,
				InputHex:             comparison.InputHex, BorOutputHex: comparison.Bor.OutputHex,
				BorError: comparison.Bor.Error, GnarkIdentity: comparison.Gnark.Identity,
				GnarkError: comparison.Gnark.Error, BlstIdentity: comparison.Blst.Identity,
				BlstError: comparison.Blst.Error,
			})
		}
	}
	return report, nil
}

type batch5AVerificationCache struct {
	g1 map[string][]byte
	g2 map[string][]byte
}

func compareBatch5ACase(testCase corpus.Batch5ACase, cache *batch5AVerificationCache) (Batch5ADifferentialCase, bool, error) {
	if testCase.TupleCount != len(testCase.Tuples) {
		return Batch5ADifferentialCase{}, false, fmt.Errorf("declared tuple count %d does not match %d scalar tuples", testCase.TupleCount, len(testCase.Tuples))
	}
	input := make([]byte, 0, testCase.TupleCount*384)
	scalarPairs := make([]ScalarPair, 0, len(testCase.Tuples))
	encodedPairs := make([]AffinePair, 0, len(testCase.Tuples))
	g1Generator := reference.G1Generator()
	g2Generator := reference.G2Generator()
	for i, tuple := range testCase.Tuples {
		g1, err := hex.DecodeString(tuple.G1EncodingHex)
		if err != nil {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d G1 encoding: %w", i, err)
		}
		g2, err := hex.DecodeString(tuple.G2EncodingHex)
		if err != nil {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d G2 encoding: %w", i, err)
		}
		if len(g1) != 128 || len(g2) != 256 {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d has G1/G2 widths %d/%d, expected 128/256", i, len(g1), len(g2))
		}
		a, ok := new(big.Int).SetString(tuple.AScalarHex, 16)
		if !ok {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d has invalid G1 scalar %q", i, tuple.AScalarHex)
		}
		b, ok := new(big.Int).SetString(tuple.BScalarHex, 16)
		if !ok {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d has invalid G2 scalar %q", i, tuple.BScalarHex)
		}
		if !tuple.G1OnCurve || !tuple.G1InSubgroup || !tuple.G2OnCurve || !tuple.G2InSubgroup {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d is not marked as independently on-curve and in-subgroup", i)
		}
		a.Mod(a, reference.SubgroupOrder())
		b.Mod(b, reference.SubgroupOrder())
		g1Key, g2Key := a.Text(16), b.Text(16)
		expectedG1 := cache.g1[g1Key]
		if expectedG1 == nil {
			p := reference.G1ScalarMult(g1Generator, a)
			if !reference.G1OnCurve(p) || !reference.G1InSubgroup(p) {
				return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d independently generated G1 point is outside reference subgroup", i)
			}
			expectedG1 = encodeG1(p)
			cache.g1[g1Key] = expectedG1
		}
		expectedG2 := cache.g2[g2Key]
		if expectedG2 == nil {
			q := reference.G2ScalarMult(g2Generator, b)
			if !reference.G2OnCurve(q) || !reference.G2InSubgroup(q) {
				return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d independently generated G2 point is outside reference subgroup", i)
			}
			expectedG2 = encodeG2(q)
			cache.g2[g2Key] = expectedG2
		}
		if !bytesEqual(g1, expectedG1) || !bytesEqual(g2, expectedG2) {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("tuple %d encoded point does not match its independent scalar multiple", i)
		}
		input = append(input, g1...)
		input = append(input, g2...)
		scalarPairs = append(scalarPairs, ScalarPair{G1Scalar: a, G2Scalar: b})
		encodedPairs = append(encodedPairs, AffinePair{G1: g1, G2: g2})
	}
	if len(input) == 0 || len(input)%384 != 0 {
		return Batch5ADifferentialCase{}, false, fmt.Errorf("assembled input has invalid length %d", len(input))
	}
	exponent := PairingProductExponent(scalarPairs)
	mathematicalIdentity := exponent.Sign() == 0
	corpusExponent, ok := new(big.Int).SetString(testCase.ExpectedExponentHex, 16)
	if !ok {
		return Batch5ADifferentialCase{}, false, fmt.Errorf("invalid serialized expected exponent %q", testCase.ExpectedExponentHex)
	}
	exponentMatchesCorpus := exponent.Cmp(corpusExponent) == 0 && mathematicalIdentity == testCase.ExpectedIdentity
	inputHash := sha256.Sum256(input)
	result := Batch5ADifferentialCase{
		Name: testCase.Name, Category: testCase.Category,
		TupleCount: len(scalarPairs), InputLength: len(input),
		InputSHA256: hex.EncodeToString(inputHash[:]), InputHex: hex.EncodeToString(input),
		MathematicalExponent: exponent.Text(16), MathematicalIdentity: mathematicalIdentity,
		CorpusExpectedIdentity: testCase.ExpectedIdentity,
		CorpusExpectedExponent: testCase.ExpectedExponentHex,
		ExpectedMatchesCorpus:  exponentMatchesCorpus,
	}
	borOutput, borErr := boradapter.RunPairing(input)
	result.Bor = Batch5ABorResult{
		RunReturnedNoError: borErr == nil,
		OutputHex:          hex.EncodeToString(borOutput), OutputLength: len(borOutput),
	}
	if borErr != nil {
		result.Bor.Error = borErr.Error()
	}
	if borErr == nil && len(borOutput) == 32 {
		if allZeroBytes(borOutput) {
			result.Bor.OutputWordValid = true
			isOne := false
			result.Bor.OutputIsOne = &isOne
		} else if isPairingOneWord(borOutput) {
			result.Bor.OutputWordValid = true
			isOne := true
			result.Bor.OutputIsOne = &isOne
		}
	}
	if result.Bor.OutputWordValid && borErr == nil {
		// OutputIsOne is non-nil only for the two canonical 32-byte result words.
		if result.Bor.OutputIsOne == nil {
			return Batch5ADifferentialCase{}, false, fmt.Errorf("internal error: valid output word lacks decoded identity bit")
		}
	}

	gnarkP, gnarkQ, gnarkErr := parseGnarkPairs(input)
	if gnarkErr != nil {
		result.Gnark = Batch5ABackendResult{Applicable: true, Error: gnarkErr.Error()}
	} else {
		identity, err := bls12381.PairingCheck(gnarkP, gnarkQ)
		result.Gnark = Batch5ABackendResult{Applicable: true}
		if err != nil {
			result.Gnark.Error = err.Error()
		} else {
			result.Gnark.Identity = &identity
		}
	}
	blstIdentity, blstErr := blstPairingCheck(encodedPairs)
	result.Blst = Batch5ABackendResult{Applicable: true}
	if blstErr != nil {
		result.Blst.Error = blstErr.Error()
	} else {
		result.Blst.Identity = &blstIdentity
	}

	if result.Bor.OutputIsOne != nil && result.Gnark.Identity != nil && result.Blst.Identity != nil {
		agree := *result.Bor.OutputIsOne == *result.Gnark.Identity && *result.Bor.OutputIsOne == *result.Blst.Identity
		result.ImplementationsAgree = &agree
	}
	result.AllMatchMathematics = result.ExpectedMatchesCorpus && result.Bor.RunReturnedNoError && result.Bor.OutputWordValid && result.Bor.OutputIsOne != nil && *result.Bor.OutputIsOne == mathematicalIdentity && result.Gnark.Identity != nil && *result.Gnark.Identity == mathematicalIdentity && result.Blst.Identity != nil && *result.Blst.Identity == mathematicalIdentity
	return result, mathematicalIdentity, nil
}

func isPairingOneWord(output []byte) bool {
	if len(output) != 32 || output[31] != 1 {
		return false
	}
	for _, b := range output[:31] {
		if b != 0 {
			return false
		}
	}
	return true
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func discrepancyClass(result Batch5ADifferentialCase) string {
	if !result.MathematicalIdentity && result.Bor.RunReturnedNoError && boolValue(result.Bor.OutputIsOne) {
		return "false-pairing-acceptance"
	}
	if result.ImplementationsAgree != nil && !*result.ImplementationsAgree {
		return "backend-disagreement"
	}
	if !result.ExpectedMatchesCorpus {
		return "corpus-expected-value-disagreement"
	}
	return "mathematical-or-production-disagreement"
}
