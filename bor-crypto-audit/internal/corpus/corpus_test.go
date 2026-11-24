package corpus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"bor-crypto-audit/internal/reference"
)

func TestCorpusIsDeterministicAndClassified(t *testing.T) {
	first, err := Marshal()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("corpus output changed across runs with the same seed")
	}

	doc, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	if doc.Seed != Seed || len(doc.Cases) < 40 {
		t.Fatalf("unexpected corpus header or size: seed=%q cases=%d", doc.Seed, len(doc.Cases))
	}
	byName := make(map[string]Case, len(doc.Cases))
	for _, testCase := range doc.Cases {
		byName[testCase.Name] = testCase
		if testCase.ByteLength*2 != len(testCase.EncodingHex) {
			t.Errorf("%s: byte length does not match serialized input", testCase.Name)
		}
	}

	for _, name := range []string{
		"field-zero", "field-one", "field-p-minus-1", "field-p", "field-p-plus-1", "field-max-384-bit",
		"field-nonzero-leading-16-bytes", "field-invalid-length-63", "g1-invalid-point-length-127",
		"g2-invalid-point-length-255", "g1-canonical-infinity", "g2-canonical-infinity",
		"g1-standard-generator", "g2-standard-generator", "g2-swap-x-coefficients", "g2-swap-y-coefficients",
		"g1-deterministic-full-curve-sample-2", "g2-deterministic-full-curve-sample-0",
	} {
		if _, ok := byName[name]; !ok {
			t.Errorf("required corpus case is absent: %s", name)
		}
	}

	for _, name := range []string{"g1-standard-generator", "g2-standard-generator", "g1-generator-scalar-2", "g2-generator-scalar-2"} {
		classification := byName[name].Classification
		if classification.Label != "on-curve-subgroup" || !boolValue(classification.OnCurve) || !boolValue(classification.InSubgroup) {
			t.Errorf("%s is not classified as a subgroup point: %+v", name, classification)
		}
	}
	for _, name := range []string{"g1-deterministic-full-curve-sample-2", "g2-deterministic-full-curve-sample-0"} {
		classification := byName[name].Classification
		if classification.Label != "on-curve-outside-subgroup" || !boolValue(classification.OnCurve) || boolValue(classification.InSubgroup) {
			t.Errorf("%s is not classified as on-curve outside the subgroup: %+v", name, classification)
		}
		if strings.Contains(byName[name].Generation, "hash-to-curve") {
			t.Errorf("%s was not generated from direct full-curve sampling", name)
		}
	}
	for _, name := range []string{"g1-degenerate-zero-one", "g1-degenerate-one-zero", "g2-degenerate-zero-one", "g2-degenerate-one-zero", "g2-swap-x-coefficients", "g2-swap-y-coefficients"} {
		if got := byName[name].Classification.Label; got != "off-curve" {
			t.Errorf("%s classification = %s, want off-curve", name, got)
		}
	}
	for _, name := range []string{"field-zero", "field-one", "field-p-minus-1"} {
		if !boolValue(byName[name].Classification.CoordinateElementsValid) {
			t.Errorf("%s should be a canonical field encoding", name)
		}
	}
	for _, name := range []string{"field-p", "field-p-plus-1", "field-max-384-bit", "field-nonzero-leading-16-bytes"} {
		if boolValue(byName[name].Classification.CoordinateElementsValid) {
			t.Errorf("%s should be a noncanonical field encoding", name)
		}
	}
	for _, name := range []string{"g1-x-p", "g1-x-p-plus-1", "g1-x-max-384-bit", "g2-x-c0-p", "g2-x-c0-p-plus-1", "g2-x-c0-max-384-bit"} {
		if byName[name].Classification.Label != "noncanonical-coordinate-field-element" {
			t.Errorf("%s should have a noncanonical coordinate", name)
		}
	}
	for _, name := range []string{"g1-canonical-infinity", "g2-canonical-infinity"} {
		classification := byName[name].Classification
		if classification.Label != "canonical-infinity" || !boolValue(classification.Infinity) || !boolValue(classification.InSubgroup) {
			t.Errorf("%s is not classified as canonical infinity: %+v", name, classification)
		}
	}
}

func boolValue(value *bool) bool { return value != nil && *value }

func TestOffSubgroupSweepIsDeterministicAndMathematicallyClassified(t *testing.T) {
	first, err := BuildOffSubgroupSweep(3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildOffSubgroupSweep(3)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("off-subgroup sweep changed for the same seed")
	}
	if len(first.Cases) != 6 {
		t.Fatalf("generated %d cases, want 6", len(first.Cases))
	}
	for _, testCase := range first.Cases {
		encoded, err := hex.DecodeString(testCase.EncodingHex)
		if err != nil {
			t.Fatal(err)
		}
		if testCase.Curve == "G1" {
			point := reference.G1Point{X: new(big.Int).SetBytes(encoded[:64]), Y: new(big.Int).SetBytes(encoded[64:])}
			if !reference.G1OnCurve(point) || reference.G1InSubgroup(point) {
				t.Errorf("%s failed independent G1 [r]P classification", testCase.Name)
			}
		} else {
			point := reference.G2Point{
				X: reference.NewFp2(new(big.Int).SetBytes(encoded[:64]), new(big.Int).SetBytes(encoded[64:128])),
				Y: reference.NewFp2(new(big.Int).SetBytes(encoded[128:192]), new(big.Int).SetBytes(encoded[192:])),
			}
			if !reference.G2OnCurve(point) || reference.G2InSubgroup(point) {
				t.Errorf("%s failed independent G2 [r]P classification", testCase.Name)
			}
		}
	}
}

func TestCurveMutationSweepIsDeterministicAndMathematicallyClassified(t *testing.T) {
	first, err := BuildCurveMutationSweep(4)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCurveMutationSweep(4)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("curve mutation sweep changed for the same deterministic deltas")
	}
	if len(first.Cases) == 0 {
		t.Fatal("curve mutation sweep generated no on-curve samples")
	}
	curves := map[string]int{}
	for _, testCase := range first.Cases {
		curves[testCase.Curve]++
		if testCase.Classification.Label != "on-curve-outside-subgroup" || !boolValue(testCase.Classification.OnCurve) || boolValue(testCase.Classification.InSubgroup) {
			t.Errorf("%s has unexpected independent classification: %+v", testCase.Name, testCase.Classification)
		}
		encoded, err := hex.DecodeString(testCase.EncodingHex)
		if err != nil {
			t.Fatal(err)
		}
		if testCase.Curve == "G1" {
			point := reference.G1Point{X: new(big.Int).SetBytes(encoded[:64]), Y: new(big.Int).SetBytes(encoded[64:])}
			if !reference.G1OnCurve(point) || reference.G1InSubgroup(point) {
				t.Errorf("%s failed independent G1 [r]P classification", testCase.Name)
			}
		} else {
			point := reference.G2Point{
				X: reference.NewFp2(new(big.Int).SetBytes(encoded[:64]), new(big.Int).SetBytes(encoded[64:128])),
				Y: reference.NewFp2(new(big.Int).SetBytes(encoded[128:192]), new(big.Int).SetBytes(encoded[192:])),
			}
			if !reference.G2OnCurve(point) || reference.G2InSubgroup(point) {
				t.Errorf("%s failed independent G2 [r]P classification", testCase.Name)
			}
		}
	}
	if curves["G1"] == 0 || curves["G2"] == 0 {
		t.Fatalf("mutation sweep must include both groups, got %+v", curves)
	}
}
