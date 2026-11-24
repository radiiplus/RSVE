package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"bor-crypto-audit/internal/analysis"
	"bor-crypto-audit/internal/corpus"
)

type corpusSummary struct {
	SchemaVersion          int            `json:"schema_version"`
	Seed                   string         `json:"seed"`
	PRNG                   string         `json:"prng"`
	SubgroupOrderHex       string         `json:"subgroup_order_hex"`
	CaseCount              int            `json:"case_count"`
	TotalTuples            int            `json:"total_tuples"`
	TupleCountDistribution map[string]int `json:"tuple_count_distribution"`
	CategoryCounts         map[string]int `json:"category_counts"`
	IdentityCases          int            `json:"mathematical_identity_cases"`
	NonIdentityCases       int            `json:"mathematical_nonidentity_cases"`
	G1PointOccurrences     int            `json:"validated_g1_point_occurrences"`
	G2PointOccurrences     int            `json:"validated_g2_point_occurrences"`
	UniqueG1Encodings      int            `json:"unique_g1_point_encodings"`
	UniqueG2Encodings      int            `json:"unique_g2_point_encodings"`
}

func main() {
	seed := flag.String("seed", corpus.Batch5ASeed, "deterministic corpus seed")
	corpusPath := flag.String("corpus-out", "testdata/batch5a/pairing-products.json", "serialized corpus path")
	reportsDir := flag.String("reports-dir", "reports/batch5a", "Batch 5A report directory")
	flag.Parse()

	doc, err := corpus.BuildBatch5ACorpus(*seed)
	check(err)
	check(writeJSON(*corpusPath, doc))
	check(writeJSON(filepath.Join(*reportsDir, "corpus-summary.json"), summarize(doc)))

	comparison, err := analysis.CompareBatch5ACorpus(doc)
	check(err)
	check(writeJSON(filepath.Join(*reportsDir, "differential-results.json"), comparison))
	metamorphic, err := analysis.BuildBatch5AMetamorphic()
	check(err)
	check(writeJSON(filepath.Join(*reportsDir, "metamorphic-results.json"), metamorphic))
	check(os.WriteFile(filepath.Join(*reportsDir, "discrepancy-analysis.md"), []byte(discrepancyAnalysis(comparison, metamorphic)), 0o644))
	check(os.WriteFile(filepath.Join(*reportsDir, "final-assessment.md"), []byte(finalAssessment(comparison, metamorphic, *seed, *corpusPath)), 0o644))
	fmt.Printf("Batch 5A: %d cases, %d tuples; false acceptances=%d, backend disagreements=%d, metamorphic relations=%d/%d\n", comparison.CaseCount, comparison.TupleCount, comparison.FalseAcceptanceCount, comparison.BackendDisagreementCount, metamorphic.RelationCount, metamorphic.RelationCount)
}

func summarize(doc corpus.Batch5ACorpus) corpusSummary {
	summary := corpusSummary{
		SchemaVersion: doc.SchemaVersion, Seed: doc.Seed, PRNG: doc.PRNG,
		SubgroupOrderHex: doc.SubgroupOrderHex, CaseCount: len(doc.Cases),
		TupleCountDistribution: map[string]int{}, CategoryCounts: map[string]int{},
	}
	uniqueG1 := map[string]struct{}{}
	uniqueG2 := map[string]struct{}{}
	for _, testCase := range doc.Cases {
		summary.TotalTuples += testCase.TupleCount
		summary.TupleCountDistribution[fmt.Sprint(testCase.TupleCount)]++
		summary.CategoryCounts[testCase.Category]++
		if testCase.ExpectedIdentity {
			summary.IdentityCases++
		} else {
			summary.NonIdentityCases++
		}
		for _, tuple := range testCase.Tuples {
			if tuple.G1OnCurve && tuple.G1InSubgroup {
				summary.G1PointOccurrences++
				uniqueG1[tuple.G1EncodingHex] = struct{}{}
			}
			if tuple.G2OnCurve && tuple.G2InSubgroup {
				summary.G2PointOccurrences++
				uniqueG2[tuple.G2EncodingHex] = struct{}{}
			}
		}
	}
	summary.UniqueG1Encodings = len(uniqueG1)
	summary.UniqueG2Encodings = len(uniqueG2)
	return summary
}

func discrepancyAnalysis(report analysis.Batch5ADifferentialReport, metamorphic analysis.Batch5AMetamorphicReport) string {
	text := fmt.Sprintf("# Batch 5A Discrepancy Analysis\n\nCases: %d. Tuple executions: %d. Bor `Run` errors: %d. Backend disagreements: %d.\n\nCritical condition: mathematical product is nonidentity while Bor returns no error and the complete output word is `0x00...01`. Matches found: %d.\n\nMetamorphic checks: %d backend relations; all preserved: %t. Details are in `metamorphic-results.json`.\n\n", report.CaseCount, report.TupleCount, report.BorRunErrorCount, report.BackendDisagreementCount, report.FalseAcceptanceCount, metamorphic.RelationCount, metamorphic.AllRelationsHold)
	if len(report.Discrepancies) == 0 && metamorphic.AllRelationsHold {
		return text + "No discrepancies were recorded. Exact inputs and all output bytes are in `differential-results.json`.\n"
	}
	text += "Discrepancies are classified below. Exact serialized inputs and implementation outputs are retained in `differential-results.json`.\n\n| Case | Class | Mathematical identity | Exponent mod r | Bor error |\n| --- | --- | ---: | --- | --- |\n"
	for _, item := range report.Discrepancies {
		errorText := item.BorError
		if errorText == "" {
			errorText = "none"
		}
		text += fmt.Sprintf("| `%s` | `%s` | %t | `%s` | `%s` |\n", item.CaseName, item.Class, item.MathematicalIdentity, item.MathematicalExponent, errorText)
	}
	return text
}

func finalAssessment(report analysis.Batch5ADifferentialReport, metamorphic analysis.Batch5AMetamorphicReport, seed, corpusPath string) string {
	status := "NO DISCREPANCY FOUND IN TESTED SCOPE"
	if report.FalseAcceptanceCount > 0 {
		status = "FALSE PAIRING ACCEPTANCE FOUND"
	} else if report.BackendDisagreementCount > 0 || len(report.Discrepancies) > 0 || !metamorphic.AllRelationsHold {
		status = "IMPLEMENTATION DISAGREEMENT FOUND; NO FALSE ACCEPTANCE"
	}
	return fmt.Sprintf("# Batch 5A Final Assessment\n\n**%s**\n\n## Evidence\n\n- Corpus seed: `%s`\n- Corpus: `%s`\n- Cases: %d; total tuples processed across cases: %d\n- Bor Run errors: %d\n- Backend disagreements: %d\n- Metamorphic backend relations: %d; all preserved: %t\n- Mathematically false Bor output-1 acceptances: %d\n- Bor source: develop commit `cefbcfd4078e7a6cdb8e7642bc26e3589e05e7ab`\n- gnark-crypto: `v0.19.2`; blst: `v0.3.17`\n\nClassification compares the complete 32-byte Bor result word to canonical zero and one words. A no-error call returning zero is a successful nonidentity equation, not proof acceptance. Implementation disagreements without a false Bor acceptance remain backend/consensus observations and do not justify an economic witness. Batch 6 was not run by this command. Assembly variant results and linked disassembly are documented separately in `assembly-determinism.md`.\n\n## Reproduction\n\n```sh\ngo run ./cmd/batch5a\ngo test ./...\ngo mod verify\n```\n", status, seed, corpusPath, report.CaseCount, report.TupleCount, report.BorRunErrorCount, report.BackendDisagreementCount, metamorphic.RelationCount, metamorphic.AllRelationsHold, report.FalseAcceptanceCount)
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
