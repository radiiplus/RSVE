package analysis

import (
	"testing"

	"bor-crypto-audit/internal/corpus"
)

func TestDeterministicCorpusComparison(t *testing.T) {
	doc, err := corpus.Build()
	if err != nil {
		t.Fatal(err)
	}
	report := Compare(doc)
	if len(report.Cases) != len(doc.Cases) {
		t.Fatalf("comparison count %d does not match corpus count %d", len(report.Cases), len(doc.Cases))
	}
	for i, result := range report.Cases {
		entry := doc.Cases[i]
		if result.Name != entry.Name || result.Pairing.InputHex == "" {
			t.Errorf("case %d lost its source entry or pairing input", i)
		}
		if entry.Kind == "point" && result.Reference.Label != entry.Classification.Label {
			t.Errorf("%s: differential reference label %q differs from corpus label %q", entry.Name, result.Reference.Label, entry.Classification.Label)
		}
		if result.Pairing.Accepted && result.Pairing.Error != "" {
			t.Errorf("%s: accepted pairing has error %q", entry.Name, result.Pairing.Error)
		}
	}

	for _, result := range report.Cases {
		if result.Reference.Label != "on-curve-outside-subgroup" {
			continue
		}
		if !result.BorDecoder.DecoderAccepted || !boolValue(result.Gnark.IsOnCurve) || boolValue(result.Gnark.IsInSubGroup) {
			t.Errorf("%s: unexpected off-subgroup differential result: %+v", result.Name, result)
		}
		if result.Pairing.Accepted {
			t.Errorf("%s: pairing Run accepted a reference off-subgroup point", result.Name)
		}
		if !contains(result.DiscrepancyCodes, "critical-reference-off-subgroup-gnark-subgroup-true") {
			// The critical condition must be visible if the measured values ever satisfy it.
			if result.BorDecoder.DecoderAccepted && boolValue(result.Gnark.IsInSubGroup) {
				t.Errorf("%s: critical subgroup discrepancy was not recorded", result.Name)
			}
		}
	}
}

func TestPairingOutputsSeparatelyFromAcceptance(t *testing.T) {
	doc, err := corpus.Build()
	if err != nil {
		t.Fatal(err)
	}
	report := Compare(doc)
	for _, name := range []string{"g1-canonical-infinity", "g2-canonical-infinity", "g1-generator-scalar-0", "g2-generator-scalar-0"} {
		result := findCase(t, report, name)
		if !result.Pairing.Accepted || result.Pairing.OutputIsTrue == nil || !*result.Pairing.OutputIsTrue {
			t.Errorf("%s: identity pairing output is not 1: %+v", name, result.Pairing)
		}
	}
	for _, name := range []string{"g1-standard-generator", "g2-standard-generator"} {
		result := findCase(t, report, name)
		if !result.Pairing.Accepted || result.Pairing.OutputIsTrue == nil || *result.Pairing.OutputIsTrue {
			t.Errorf("%s: standard generator pairing output is not 0: %+v", name, result.Pairing)
		}
	}
}

func findCase(t *testing.T, report Report, name string) Comparison {
	t.Helper()
	for _, result := range report.Cases {
		if result.Name == name {
			return result
		}
	}
	t.Fatalf("report omitted case %s", name)
	return Comparison{}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
