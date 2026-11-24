package main

import (
	"encoding/json"
	"fmt"
	"os"

	"bor-crypto-audit/internal/analysis"
)

func main() {
	batch4Path := "reports/differential/report.json"
	outputPath := "reports/pairing-differential.json"
	if len(os.Args) > 1 {
		batch4Path = os.Args[1]
	}
	if len(os.Args) > 2 {
		outputPath = os.Args[2]
	}
	data, err := os.ReadFile(batch4Path)
	check(err)
	var batch4 analysis.Report
	check(json.Unmarshal(data, &batch4))

	report, err := analysis.BuildPairingDifferential(batch4)
	check(err)
	encoded, err := json.MarshalIndent(report, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	check(os.WriteFile(outputPath, encoded, 0o644))
	fmt.Printf("wrote %d pairing comparisons to %s\n", len(report.Cases), outputPath)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
