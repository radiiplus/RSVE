package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"bor-crypto-audit/internal/analysis"
)

func main() {
	output := flag.String("out", "reports/blindspot-analysis.json", "blindspot report path")
	flag.Parse()
	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{
			"reports/differential/report.json",
			"reports/off-subgroup-sweep-report.json",
			"reports/curve-mutation-sweep-report.json",
		}
	}

	reports := make([]analysis.Report, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		check(err)
		var report analysis.Report
		check(json.Unmarshal(data, &report))
		reports = append(reports, report)
	}
	result := analysis.BuildBlindspotReport(reports, paths)
	check(result.Validate())
	encoded, err := json.MarshalIndent(result, "", "  ")
	check(err)
	check(os.MkdirAll(filepath.Dir(*output), 0o755))
	check(os.WriteFile(*output, append(encoded, '\n'), 0o644))
	fmt.Printf("analyzed %d unique point encodings across %d reports; wrote %s\n", result.UniquePoints, len(paths), *output)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
