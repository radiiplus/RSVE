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

func main() {
	inputPath := flag.String("corpus", "testdata/bls12-381-corpus.json", "serialized corpus path")
	outputPath := flag.String("out", "reports/differential/report.json", "differential report path")
	flag.Parse()

	input, err := os.ReadFile(*inputPath)
	check(err)
	var doc corpus.Document
	check(json.Unmarshal(input, &doc))

	report := analysis.Compare(doc)
	encoded, err := json.MarshalIndent(report, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	check(os.MkdirAll(filepath.Dir(*outputPath), 0o755))
	check(os.WriteFile(*outputPath, encoded, 0o644))

	if len(report.Findings) != 0 {
		minimizedDir := filepath.Join(filepath.Dir(*outputPath), "minimized")
		check(os.MkdirAll(minimizedDir, 0o755))
		for _, finding := range report.Findings {
			name := fmt.Sprintf("%s-%s.json", finding.CaseName, finding.Code)
			data, err := json.MarshalIndent(finding, "", "  ")
			check(err)
			check(os.WriteFile(filepath.Join(minimizedDir, name), append(data, '\n'), 0o644))
		}
	}
	fmt.Printf("compared %d corpus cases; recorded %d discrepancies\n", len(report.Cases), len(report.Findings))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
