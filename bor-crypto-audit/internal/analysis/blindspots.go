package analysis

import (
	"encoding/hex"
	"fmt"
	"sort"

	"bor-crypto-audit/internal/boradapter"
)

type BlindspotReport struct {
	SchemaVersion int                    `json:"schema_version"`
	SourceReports []string               `json:"source_reports"`
	UniquePoints  int                    `json:"unique_points"`
	Sets          map[string][]string    `json:"sets"`
	SetCounts     map[string]int         `json:"set_counts"`
	Differences   map[string][]string    `json:"set_differences"`
	Intersections map[string][]string    `json:"set_intersections"`
	TupleProbes   []TupleAcceptanceProbe `json:"tuple_acceptance_probes"`
	Scope         string                 `json:"scope"`
}

type TupleAcceptanceProbe struct {
	Name               string `json:"name"`
	InputHex           string `json:"input_hex"`
	RunReturnedNoError bool   `json:"run_returned_no_error"`
	PairingResultIsOne *bool  `json:"pairing_result_is_one,omitempty"`
	Error              string `json:"error,omitempty"`
	OutputHex          string `json:"output_hex,omitempty"`
}

type pointSets struct {
	key, curve                        string
	canonical, onCurve, refSubgroup   bool
	decoderAccepted, gnarkOnCurve     bool
	gnarkSubgroup, productionAccepted bool
	infinity                          bool
}

// BuildBlindspotReport summarizes the exact point-set relationships visible
// in differential reports and checks whether tuple ordering changes rejection.
func BuildBlindspotReport(reports []Report, paths []string) BlindspotReport {
	pointsByKey := make(map[string]pointSets)
	for _, report := range reports {
		for _, c := range report.Cases {
			if !c.Reference.Applicable || c.Reference.CoordinateCanonical == nil || c.Reference.OnCurve == nil || c.Reference.InSubgroup == nil {
				continue
			}
			key := c.PointUnderTestCurve + ":" + c.PointUnderTestHex
			point := pointSets{
				key: key, curve: c.PointUnderTestCurve,
				canonical:          *c.Reference.CoordinateCanonical,
				onCurve:            *c.Reference.OnCurve,
				refSubgroup:        *c.Reference.InSubgroup,
				infinity:           boolValue(c.Reference.Infinity),
				decoderAccepted:    c.BorDecoder.DecoderAccepted,
				gnarkOnCurve:       boolValue(c.Gnark.IsOnCurve),
				gnarkSubgroup:      boolValue(c.Gnark.IsInSubGroup),
				productionAccepted: c.Pairing.Accepted,
			}
			pointsByKey[key] = point
		}
	}

	out := BlindspotReport{
		SchemaVersion: 1,
		SourceReports: append([]string{}, paths...),
		UniquePoints:  len(pointsByKey),
		Sets:          map[string][]string{},
		SetCounts:     map[string]int{},
		Differences:   map[string][]string{},
		Intersections: map[string][]string{},
		Scope:         "Observed point encodings only. The reference set is canonical, on-curve points satisfying ordinary [r]P=O. Tuple probes test validation acceptance and do not assert pairing mathematics.",
	}
	for _, point := range pointsByKey {
		ref := point.canonical && point.onCurve && point.refSubgroup
		gnark := point.canonical && point.gnarkOnCurve && point.gnarkSubgroup
		decoder := point.decoderAccepted
		production := point.productionAccepted
		add := func(name string, included bool) {
			if included {
				out.Sets[name] = append(out.Sets[name], point.key)
			}
		}
		add("reference_mathematical_domain", ref)
		add("gnark_optimized_domain", gnark)
		add("bor_decoder_acceptance", decoder)
		add("bor_pairing_run_acceptance", production)
		add("any_layer_acceptance_union", ref || gnark || decoder || production)
		add("all_layer_acceptance_intersection", ref && gnark && decoder && production)
		add("off_subgroup_on_curve", point.canonical && point.onCurve && !point.refSubgroup)
		add("canonical_infinity", point.canonical && point.infinity)
	}
	for name, members := range out.Sets {
		sort.Strings(members)
		out.SetCounts[name] = len(members)
	}
	out.Differences["gnark_optimized_domain_minus_reference"] = difference(out.Sets["gnark_optimized_domain"], out.Sets["reference_mathematical_domain"])
	out.Differences["reference_minus_gnark_optimized_domain"] = difference(out.Sets["reference_mathematical_domain"], out.Sets["gnark_optimized_domain"])
	out.Differences["decoder_acceptance_minus_reference"] = difference(out.Sets["bor_decoder_acceptance"], out.Sets["reference_mathematical_domain"])
	out.Differences["production_acceptance_minus_reference"] = difference(out.Sets["bor_pairing_run_acceptance"], out.Sets["reference_mathematical_domain"])
	out.Intersections["reference_and_gnark"] = intersection(out.Sets["reference_mathematical_domain"], out.Sets["gnark_optimized_domain"])
	out.Intersections["decoder_and_reference"] = intersection(out.Sets["bor_decoder_acceptance"], out.Sets["reference_mathematical_domain"])
	out.Intersections["production_and_reference"] = intersection(out.Sets["bor_pairing_run_acceptance"], out.Sets["reference_mathematical_domain"])
	out.TupleProbes = buildTupleProbes(pointsByKey)
	return out
}

func buildTupleProbes(points map[string]pointSets) []TupleAcceptanceProbe {
	var g1Sub, g2Sub, g1Off, g2Off string
	keys := make([]string, 0, len(points))
	for key := range points {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		point := points[key]
		if !point.canonical || !point.onCurve {
			continue
		}
		if point.refSubgroup {
			if !point.infinity {
				if point.curve == "G1" && g1Sub == "" {
					g1Sub = point.key[len("G1:"):]
				}
				if point.curve == "G2" && g2Sub == "" {
					g2Sub = point.key[len("G2:"):]
				}
			}
		} else {
			if point.curve == "G1" && g1Off == "" {
				g1Off = point.key[len("G1:"):]
			}
			if point.curve == "G2" && g2Off == "" {
				g2Off = point.key[len("G2:"):]
			}
		}
	}
	if g1Sub == "" || g2Sub == "" || g1Off == "" || g2Off == "" {
		return nil
	}
	valid := append(decodeHex(g1Sub), decodeHex(g2Sub)...)
	badG1 := append(decodeHex(g1Off), decodeHex(g2Sub)...)
	badG2 := append(decodeHex(g1Sub), decodeHex(g2Off)...)
	badBoth := append(decodeHex(g1Off), decodeHex(g2Off)...)
	return []TupleAcceptanceProbe{
		runProbe("valid tuple", valid),
		runProbe("valid tuple then off-subgroup G1 tuple", append(append(append([]byte{}, valid...), badG1...), valid...)),
		runProbe("off-subgroup G1 tuple then valid tuple", append(append(append([]byte{}, badG1...), valid...), valid...)),
		runProbe("valid tuple then off-subgroup G2 tuple", append(append(append([]byte{}, valid...), badG2...), valid...)),
		runProbe("off-subgroup G2 tuple then valid tuple", append(append(append([]byte{}, badG2...), valid...), valid...)),
		runProbe("one tuple with off-subgroup G1 and G2", badBoth),
	}
}

func runProbe(name string, input []byte) TupleAcceptanceProbe {
	output, err := boradapter.RunPairing(input)
	probe := TupleAcceptanceProbe{Name: name, InputHex: hex.EncodeToString(input), RunReturnedNoError: err == nil, OutputHex: hex.EncodeToString(output)}
	if err != nil {
		probe.Error = err.Error()
	} else if len(output) == 32 {
		isOne := output[31] == 1
		probe.PairingResultIsOne = &isOne
	}
	return probe
}

func difference(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, item := range right {
		rightSet[item] = struct{}{}
	}
	var result []string
	for _, item := range left {
		if _, found := rightSet[item]; !found {
			result = append(result, item)
		}
	}
	return result
}

func intersection(left, right []string) []string {
	leftSet := make(map[string]struct{}, len(left))
	for _, item := range left {
		leftSet[item] = struct{}{}
	}
	var result []string
	for _, item := range right {
		if _, found := leftSet[item]; found {
			result = append(result, item)
		}
	}
	return result
}

func (r BlindspotReport) Validate() error {
	if r.UniquePoints == 0 {
		return fmt.Errorf("no comparable points in source reports")
	}
	return nil
}
