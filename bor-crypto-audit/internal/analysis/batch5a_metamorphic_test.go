package analysis

import "testing"

func TestBatch5AMetamorphicRelations(t *testing.T) {
	report, err := BuildBatch5AMetamorphic()
	if err != nil {
		t.Fatal(err)
	}
	if report.CaseCount != 8 || report.RelationCount != 24 {
		t.Fatalf("unexpected metamorphic coverage: cases=%d backend relations=%d", report.CaseCount, report.RelationCount)
	}
	if !report.AllRelationsHold {
		for _, testCase := range report.Cases {
			if !testCase.RelationHolds {
				t.Errorf("%s: relation failed: Bor=%+v gnark=%+v blst=%+v", testCase.Name, testCase.Bor, testCase.Gnark, testCase.Blst)
			}
		}
	}
	for _, testCase := range report.Cases {
		if testCase.Bor.Left.Identity == nil || testCase.Bor.Right.Identity == nil || testCase.Gnark.Left.Identity == nil || testCase.Gnark.Right.Identity == nil || testCase.Blst.Left.Identity == nil || testCase.Blst.Right.Identity == nil {
			t.Errorf("%s: backend result was not a complete identity classification", testCase.Name)
		}
	}
}
