package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"bor-crypto-audit/internal/corpus"
)

func main() {
	count := flag.Int("per-group", 128, "number of off-subgroup points to generate per group")
	output := flag.String("out", "testdata/off-subgroup-sweep.json", "serialized point corpus path")
	flag.Parse()

	doc, err := corpus.BuildOffSubgroupSweep(*count)
	check(err)
	encoded, err := json.MarshalIndent(doc, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	check(os.WriteFile(*output, encoded, 0o644))
	fmt.Printf("wrote %d on-curve off-subgroup points to %s\n", len(doc.Cases), *output)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
