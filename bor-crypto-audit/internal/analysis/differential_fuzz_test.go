package analysis

import (
	"testing"

	"bor-crypto-audit/internal/boradapter"
	"bor-crypto-audit/internal/corpus"
	"bor-crypto-audit/internal/reference"
)

func FuzzG1SubgroupDifferential(f *testing.F) {
	doc, err := corpus.Build()
	if err != nil {
		f.Fatal(err)
	}
	for _, entry := range doc.Cases {
		if entry.Curve == "G1" && entry.Kind == "point" {
			f.Add(decodeHex(entry.EncodingHex))
		}
		if entry.Curve == "Fp" && entry.Kind == "field-element" {
			encoded := decodeHex(entry.EncodingHex)
			if len(encoded) == 64 {
				f.Add(append(encoded, make([]byte, 64)...))
			}
		}
	}
	generator := encodeG1(reference.G1Generator())
	for _, offset := range []int{47, 63, 111, 127} {
		mutated := append([]byte{}, generator...)
		mutated[offset]++
		f.Add(mutated)
	}
	g2 := encodeG2(reference.G2Generator())
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 256 {
			return
		}
		ref := classifyReference("G1", input)
		inspection := boradapter.InspectG1(input)
		pairingInput := append(append([]byte{}, input...), g2...)
		_, pairingErr := boradapter.RunPairing(pairingInput)
		assertGroupAgreement(t, "G1", ref, inspection, pairingErr)
	})
}

func FuzzG2SubgroupDifferential(f *testing.F) {
	doc, err := corpus.Build()
	if err != nil {
		f.Fatal(err)
	}
	for _, entry := range doc.Cases {
		if entry.Curve == "G2" && entry.Kind == "point" {
			f.Add(decodeHex(entry.EncodingHex))
		}
	}
	generator := encodeG2(reference.G2Generator())
	for _, offset := range []int{47, 111, 175, 239} {
		mutated := append([]byte{}, generator...)
		mutated[offset]++
		f.Add(mutated)
	}
	g1 := encodeG1(reference.G1Generator())
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 512 {
			return
		}
		ref := classifyReference("G2", input)
		inspection := boradapter.InspectG2(input)
		pairingInput := append(append([]byte{}, g1...), input...)
		_, pairingErr := boradapter.RunPairing(pairingInput)
		assertGroupAgreement(t, "G2", ref, inspection, pairingErr)
	})
}

func assertGroupAgreement(t *testing.T, curve string, ref ReferenceResult, inspection boradapter.PointInspection, pairingErr error) {
	t.Helper()
	if !ref.Applicable {
		if inspection.DecoderAccepted {
			t.Fatalf("%s malformed point length accepted by Bor decoder", curve)
		}
		if pairingErr == nil {
			t.Fatalf("%s malformed point length accepted by pairing Run", curve)
		}
		return
	}
	if !boolValue(ref.CoordinateCanonical) {
		if inspection.DecoderAccepted || inspection.GnarkCoordinatesValid || pairingErr == nil {
			t.Fatalf("%s noncanonical point encoding was accepted: %+v", curve, inspection)
		}
		return
	}
	if !boolValue(ref.OnCurve) {
		if inspection.DecoderAccepted || boolValue(inspection.GnarkIsOnCurve) || pairingErr == nil {
			t.Fatalf("%s off-curve point classification disagrees: %+v", curve, inspection)
		}
		return
	}
	if !inspection.DecoderAccepted || !boolValue(inspection.GnarkIsOnCurve) {
		t.Fatalf("%s on-curve point was rejected: %+v", curve, inspection)
	}
	if boolValue(ref.InSubgroup) != boolValue(inspection.GnarkIsInSubGroup) {
		t.Fatalf("%s subgroup mismatch: reference=%v gnark=%v", curve, boolValue(ref.InSubgroup), boolValue(inspection.GnarkIsInSubGroup))
	}
	if (pairingErr == nil) != boolValue(ref.InSubgroup) {
		t.Fatalf("%s pairing acceptance mismatch for subgroup=%v: err=%v", curve, boolValue(ref.InSubgroup), pairingErr)
	}
}
