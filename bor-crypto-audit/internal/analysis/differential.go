package analysis

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"bor-crypto-audit/internal/boradapter"
	"bor-crypto-audit/internal/corpus"
	"bor-crypto-audit/internal/reference"
)

type Report struct {
	SchemaVersion   int          `json:"schema_version"`
	Seed            string       `json:"seed"`
	Source          string       `json:"source"`
	FuzzResultsPath string       `json:"fuzz_results_path"`
	ScopeNote       string       `json:"scope_note"`
	Cases           []Comparison `json:"cases"`
	Findings        []Finding    `json:"findings"`
}

type Comparison struct {
	Name                string                     `json:"name"`
	CorpusCurve         string                     `json:"corpus_curve"`
	Kind                string                     `json:"kind"`
	CorpusInputHex      string                     `json:"corpus_input_hex"`
	PointUnderTestCurve string                     `json:"point_under_test_curve"`
	PointUnderTestHex   string                     `json:"point_under_test_hex"`
	Reference           ReferenceResult            `json:"reference"`
	BorDecoder          boradapter.PointInspection `json:"bor_decoder"`
	Gnark               GnarkResult                `json:"gnark"`
	Pairing             PairingResult              `json:"pairing"`
	DiscrepancyCodes    []string                   `json:"discrepancy_codes,omitempty"`
}

type ReferenceResult struct {
	Applicable          bool   `json:"applicable"`
	Label               string `json:"label"`
	CoordinateCanonical *bool  `json:"coordinate_field_elements_canonical,omitempty"`
	OnCurve             *bool  `json:"on_curve,omitempty"`
	RPointIsInfinity    *bool  `json:"r_times_point_is_infinity,omitempty"`
	InSubgroup          *bool  `json:"in_subgroup,omitempty"`
	Infinity            *bool  `json:"infinity,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

type GnarkResult struct {
	CoordinatesValid bool   `json:"coordinates_valid"`
	FieldError       string `json:"field_error,omitempty"`
	IsOnCurve        *bool  `json:"is_on_curve,omitempty"`
	IsInSubGroup     *bool  `json:"is_in_subgroup,omitempty"`
}

type PairingResult struct {
	InputHex                   string `json:"input_hex"`
	Accepted                   bool   `json:"accepted"`
	Error                      string `json:"error,omitempty"`
	OutputHex                  string `json:"output_hex,omitempty"`
	OutputIsTrue               *bool  `json:"output_is_true,omitempty"`
	ExpectedAcceptance         bool   `json:"expected_acceptance_from_reference"`
	AcceptanceMatchesReference bool   `json:"acceptance_matches_reference"`
}

type Finding struct {
	CaseName            string `json:"case_name"`
	Code                string `json:"code"`
	Description         string `json:"description"`
	OriginalPointHex    string `json:"original_point_hex"`
	OriginalPairingHex  string `json:"original_pairing_input_hex"`
	MinimizedPointHex   string `json:"minimized_point_hex"`
	MinimizedPairingHex string `json:"minimized_pairing_input_hex"`
}

func Compare(doc corpus.Document) Report {
	report := Report{
		SchemaVersion:   1,
		Seed:            doc.Seed,
		Source:          "Bor develop cefbcfd4078e7a6cdb8e7642bc26e3589e05e7ab; extracted declarations in internal/boradapter",
		FuzzResultsPath: "reports/differential/fuzz-results.json",
		ScopeNote:       "Differential results only; absence of a discrepancy is not an exploitability determination.",
	}
	g1Generator := encodeG1(reference.G1Generator())
	g2Generator := encodeG2(reference.G2Generator())
	for _, entry := range doc.Cases {
		curve := entry.Curve
		point := decodeHex(entry.EncodingHex)
		if entry.Kind == "field-element" {
			curve = "G1"
			point = append(append([]byte{}, point...), make([]byte, 64)...)
		}
		if entry.Kind != "point" && entry.Kind != "field-element" {
			curve = "G1"
			point = append(append([]byte{}, point...), make([]byte, 128-len(point))...)
		}

		refResult := classifyReference(curve, point)
		inspection := boradapter.PointInspection{}
		if curve == "G2" {
			inspection = boradapter.InspectG2(point)
		} else {
			inspection = boradapter.InspectG1(point)
		}
		gnark := GnarkResult{
			CoordinatesValid: inspection.GnarkCoordinatesValid,
			FieldError:       inspection.GnarkFieldError,
			IsOnCurve:        inspection.GnarkIsOnCurve,
			IsInSubGroup:     inspection.GnarkIsInSubGroup,
		}

		pairingInput := makePairingInput(curve, point, g1Generator, g2Generator)
		output, pairingErr := boradapter.RunPairing(pairingInput)
		pairing := PairingResult{
			InputHex:  hex.EncodeToString(pairingInput),
			Accepted:  pairingErr == nil,
			OutputHex: hex.EncodeToString(output),
			ExpectedAcceptance: refResult.Applicable && boolValue(refResult.CoordinateCanonical) &&
				boolValue(refResult.OnCurve) && boolValue(refResult.InSubgroup),
		}
		if pairingErr != nil {
			pairing.Error = pairingErr.Error()
		}
		if len(output) == 32 && pairingErr == nil {
			isTrue := output[31] == 1
			pairing.OutputIsTrue = &isTrue
		}
		pairing.AcceptanceMatchesReference = pairing.Accepted == pairing.ExpectedAcceptance

		comparison := Comparison{
			Name:                entry.Name,
			CorpusCurve:         entry.Curve,
			Kind:                entry.Kind,
			CorpusInputHex:      entry.EncodingHex,
			PointUnderTestCurve: curve,
			PointUnderTestHex:   hex.EncodeToString(point),
			Reference:           refResult,
			BorDecoder:          inspection,
			Gnark:               gnark,
			Pairing:             pairing,
		}
		comparison.DiscrepancyCodes = discrepancies(refResult, inspection, pairing)
		report.Cases = append(report.Cases, comparison)
		for _, code := range comparison.DiscrepancyCodes {
			minimized := minimizePoint(curve, point, code, g1Generator, g2Generator)
			minimizedPairing := makePairingInput(curve, minimized, g1Generator, g2Generator)
			report.Findings = append(report.Findings, Finding{
				CaseName:            entry.Name,
				Code:                code,
				Description:         descriptionFor(code),
				OriginalPointHex:    hex.EncodeToString(point),
				OriginalPairingHex:  hex.EncodeToString(pairingInput),
				MinimizedPointHex:   hex.EncodeToString(minimized),
				MinimizedPairingHex: hex.EncodeToString(minimizedPairing),
			})
		}
	}
	return report
}

func classifyReference(curve string, encoded []byte) ReferenceResult {
	width, fields := 128, 2
	if curve == "G2" {
		width, fields = 256, 4
	}
	if len(encoded) != width {
		return ReferenceResult{Applicable: false, Label: "malformed-point-length", Reason: fmt.Sprintf("expected %d bytes, got %d", width, len(encoded))}
	}
	if allZero(encoded) {
		return ReferenceResult{
			Applicable: true, Label: "canonical-infinity", CoordinateCanonical: boolPtr(true),
			OnCurve: boolPtr(true), RPointIsInfinity: boolPtr(true), InSubgroup: boolPtr(true), Infinity: boolPtr(true),
		}
	}
	values := make([]*big.Int, fields)
	modulus := reference.BaseFieldModulus()
	for i := range values {
		values[i] = new(big.Int).SetBytes(encoded[i*64 : (i+1)*64])
		if values[i].Cmp(modulus) >= 0 {
			return ReferenceResult{
				Applicable: true, Label: "noncanonical-coordinate-field-element", CoordinateCanonical: boolPtr(false),
				Reason: "coordinate is greater than or equal to p",
			}
		}
	}
	if curve == "G2" {
		point := reference.G2Point{
			X: reference.NewFp2(values[0], values[1]),
			Y: reference.NewFp2(values[2], values[3]),
		}
		onCurve := reference.G2OnCurve(point)
		if !onCurve {
			return ReferenceResult{Applicable: true, Label: "off-curve", CoordinateCanonical: boolPtr(true), OnCurve: boolPtr(false), InSubgroup: boolPtr(false), Infinity: boolPtr(false)}
		}
		rInfinity := reference.G2ScalarMult(point, reference.SubgroupOrder()).Infinity
		label := "on-curve-outside-subgroup"
		if rInfinity {
			label = "on-curve-subgroup"
		}
		return ReferenceResult{Applicable: true, Label: label, CoordinateCanonical: boolPtr(true), OnCurve: boolPtr(true), RPointIsInfinity: boolPtr(rInfinity), InSubgroup: boolPtr(rInfinity), Infinity: boolPtr(false)}
	}
	point := reference.G1Point{X: values[0], Y: values[1]}
	onCurve := reference.G1OnCurve(point)
	if !onCurve {
		return ReferenceResult{Applicable: true, Label: "off-curve", CoordinateCanonical: boolPtr(true), OnCurve: boolPtr(false), InSubgroup: boolPtr(false), Infinity: boolPtr(false)}
	}
	rInfinity := reference.G1ScalarMult(point, reference.SubgroupOrder()).Infinity
	label := "on-curve-outside-subgroup"
	if rInfinity {
		label = "on-curve-subgroup"
	}
	return ReferenceResult{Applicable: true, Label: label, CoordinateCanonical: boolPtr(true), OnCurve: boolPtr(true), RPointIsInfinity: boolPtr(rInfinity), InSubgroup: boolPtr(rInfinity), Infinity: boolPtr(false)}
}

func discrepancies(ref ReferenceResult, decoder boradapter.PointInspection, pairing PairingResult) []string {
	var codes []string
	if ref.Applicable && ref.OnCurve != nil && decoder.GnarkIsOnCurve != nil && *ref.OnCurve != *decoder.GnarkIsOnCurve {
		codes = append(codes, "curve-membership-disagreement")
	}
	if ref.Applicable && boolValue(ref.OnCurve) && ref.InSubgroup != nil && decoder.GnarkIsInSubGroup != nil && *ref.InSubgroup != *decoder.GnarkIsInSubGroup {
		codes = append(codes, "subgroup-membership-disagreement")
	}
	decoderShouldAccept := ref.Applicable && boolValue(ref.CoordinateCanonical) && boolValue(ref.OnCurve)
	if ref.Applicable && decoder.DecoderAccepted != decoderShouldAccept {
		codes = append(codes, "bor-decoder-disagreement")
	}
	if ref.Applicable && !pairing.AcceptanceMatchesReference {
		codes = append(codes, "pairing-acceptance-disagreement")
	}
	if boolValue(ref.OnCurve) && ref.InSubgroup != nil && !*ref.InSubgroup && decoder.DecoderAccepted && boolValue(decoder.GnarkIsInSubGroup) {
		codes = append(codes, "critical-reference-off-subgroup-gnark-subgroup-true")
	}
	return codes
}

func minimizePoint(curve string, original []byte, code string, g1, g2 []byte) []byte {
	current := append([]byte{}, original...)
	for chunk := len(current) / 2; chunk > 0; chunk /= 2 {
		for start := 0; start < len(current); start += chunk {
			end := start + chunk
			if end > len(current) {
				end = len(current)
			}
			candidate := append([]byte{}, current...)
			clear(candidate[start:end])
			if hasFinding(curve, candidate, code, g1, g2) {
				current = candidate
			}
		}
	}
	return current
}

func hasFinding(curve string, point []byte, code string, g1, g2 []byte) bool {
	ref := classifyReference(curve, point)
	var inspection boradapter.PointInspection
	if curve == "G2" {
		inspection = boradapter.InspectG2(point)
	} else {
		inspection = boradapter.InspectG1(point)
	}
	pairInput := makePairingInput(curve, point, g1, g2)
	_, err := boradapter.RunPairing(pairInput)
	pairing := PairingResult{
		Accepted: err == nil,
		ExpectedAcceptance: ref.Applicable && boolValue(ref.CoordinateCanonical) &&
			boolValue(ref.OnCurve) && boolValue(ref.InSubgroup),
	}
	pairing.AcceptanceMatchesReference = pairing.Accepted == pairing.ExpectedAcceptance
	for _, found := range discrepancies(ref, inspection, pairing) {
		if found == code {
			return true
		}
	}
	return false
}

func makePairingInput(curve string, point, g1, g2 []byte) []byte {
	if curve == "G2" {
		out := append([]byte{}, g1...)
		return append(out, point...)
	}
	out := append([]byte{}, point...)
	return append(out, g2...)
}

func encodeG1(p reference.G1Point) []byte {
	out := make([]byte, 128)
	if p.Infinity {
		return out
	}
	putField(out[:64], p.X)
	putField(out[64:], p.Y)
	return out
}

func encodeG2(p reference.G2Point) []byte {
	out := make([]byte, 256)
	if p.Infinity {
		return out
	}
	putField(out[0:64], p.X.C0)
	putField(out[64:128], p.X.C1)
	putField(out[128:192], p.Y.C0)
	putField(out[192:256], p.Y.C1)
	return out
}

func putField(dst []byte, value *big.Int) {
	b := value.Bytes()
	copy(dst[len(dst)-len(b):], b)
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func boolPtr(value bool) *bool { return &value }

func boolValue(value *bool) bool { return value != nil && *value }

func descriptionFor(code string) string {
	switch code {
	case "curve-membership-disagreement":
		return "Reference curve membership differs from gnark IsOnCurve"
	case "subgroup-membership-disagreement":
		return "Reference [r]P membership differs from gnark IsInSubGroup"
	case "bor-decoder-disagreement":
		return "Bor decoder result differs from the independent reference point classification"
	case "pairing-acceptance-disagreement":
		return "Bor pairing Run acceptance differs from reference validity and subgroup classification"
	case "critical-reference-off-subgroup-gnark-subgroup-true":
		return "Reference point is on-curve and [r]P is not infinity, while Bor decoding succeeds and gnark IsInSubGroup returns true"
	default:
		return code
	}
}
