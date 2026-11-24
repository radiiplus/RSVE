package analysis

import (
	"testing"

	"bor-crypto-audit/internal/corpus"
)

func TestPairingDifferentialAgainstMathematics(t *testing.T) {
	report, err := BuildPairingDifferential(Report{})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range report.Cases {
		if result.MathematicalExpected == nil {
			if result.BorRun.Accepted || result.BorRun.Error == "" || result.GnarkDirect.Applicable || result.BlstDirect.Applicable {
				t.Errorf("%s: malformed length boundary was not rejected cleanly: %+v", result.Name, result)
			}
			continue
		}
		if !result.BorRun.Accepted || !result.GnarkDirect.Accepted || !result.BlstDirect.Accepted {
			t.Errorf("%s: valid pairing input was rejected: %+v", result.Name, result)
			continue
		}
		if result.BorRun.Identity == nil || result.GnarkDirect.Identity == nil || result.BlstDirect.Identity == nil {
			t.Errorf("%s: accepted pairing did not produce an identity result", result.Name)
			continue
		}
		if !*result.ImplementationsAgree || !*result.MatchesMathematics {
			t.Errorf("%s: implementations disagree with expected identity=%v: bor=%v gnark=%v blst=%v", result.Name, *result.MathematicalExpected, *result.BorRun.Identity, *result.GnarkDirect.Identity, *result.BlstDirect.Identity)
		}
		if len(result.BorRun.OutputHex) != 64 {
			t.Errorf("%s: Bor output is not 32 bytes", result.Name)
		}
	}
}

func TestBatch4AcceptedOffSubgroupFollowup(t *testing.T) {
	doc, err := corpus.Build()
	if err != nil {
		t.Fatal(err)
	}
	batch4 := Compare(doc)
	report, err := BuildPairingDifferential(batch4)
	if err != nil {
		t.Fatal(err)
	}
	if report.Batch4Followup.AcceptedCount != 0 || len(report.Batch4Followup.Cases) != 2 {
		t.Fatalf("unexpected Batch 4 off-subgroup results: %+v", report.Batch4Followup)
	}
	for _, result := range report.Batch4Followup.Cases {
		if !result.ReferenceOnCurve || result.ReferenceInSubgroup || !result.BorDecoderAccepted || result.BorPairingAccepted || result.IndependentPairingTested {
			t.Errorf("unexpected off-subgroup followup for %s: %+v", result.Name, result)
		}
	}
}
