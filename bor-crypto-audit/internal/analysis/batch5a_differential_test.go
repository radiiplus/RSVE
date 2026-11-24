package analysis

import (
	"testing"

	"bor-crypto-audit/internal/corpus"
)

func TestCompareBatch5ACorpusFocusedProducts(t *testing.T) {
	doc, err := corpus.BuildBatch5ACorpus(corpus.Batch5ASeed)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := map[string]bool{
		"random-identity-1":    true,
		"random-nonidentity-1": true,
		"near-identity-1-1":    true,
		"near-identity-1-73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000": true,
		"boundary-scalars-a0-b3": true,
		"infinity-mixed-3":       true,
	}
	focused := corpus.Batch5ACorpus{SchemaVersion: doc.SchemaVersion, Seed: doc.Seed, PRNG: doc.PRNG, SubgroupOrderHex: doc.SubgroupOrderHex}
	for _, testCase := range doc.Cases {
		if wantNames[testCase.Name] {
			focused.Cases = append(focused.Cases, testCase)
		}
	}
	if len(focused.Cases) != len(wantNames) {
		t.Fatalf("selected %d focused cases, want %d", len(focused.Cases), len(wantNames))
	}

	report, err := CompareBatch5ACorpus(focused)
	if err != nil {
		t.Fatal(err)
	}
	if report.CaseCount != len(wantNames) || report.FalseAcceptanceCount != 0 || report.BackendDisagreementCount != 0 || len(report.Discrepancies) != 0 {
		t.Fatalf("unexpected focused differential summary: cases=%d false_acceptances=%d backend_disagreements=%d discrepancies=%d", report.CaseCount, report.FalseAcceptanceCount, report.BackendDisagreementCount, len(report.Discrepancies))
	}
	for _, result := range report.Cases {
		if !result.Bor.RunReturnedNoError || !result.Bor.OutputWordValid || result.Bor.OutputIsOne == nil {
			t.Errorf("%s: invalid Bor result: %+v", result.Name, result.Bor)
		}
		if result.Gnark.Identity == nil || result.Blst.Identity == nil || !result.AllMatchMathematics {
			t.Errorf("%s: implementations did not match scalar oracle: %+v", result.Name, result)
		}
	}
}

func TestPairingOutputOneRequiresCanonicalWholeWord(t *testing.T) {
	wordOne := make([]byte, 32)
	wordOne[31] = 1
	if !isPairingOneWord(wordOne) {
		t.Fatal("canonical uint256(1) word was not recognized")
	}
	wordZero := make([]byte, 32)
	if isPairingOneWord(wordZero) {
		t.Fatal("canonical uint256(0) word was recognized as one")
	}
	malformed := append([]byte(nil), wordOne...)
	malformed[0] = 1
	if isPairingOneWord(malformed) {
		t.Fatal("noncanonical 32-byte value with final byte 1 was recognized as one")
	}
	if isPairingOneWord(wordOne[:31]) {
		t.Fatal("31-byte output was recognized as one")
	}
}
