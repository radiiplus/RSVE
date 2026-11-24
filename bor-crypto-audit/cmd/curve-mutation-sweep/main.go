package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"bor-crypto-audit/internal/corpus"
)

func main() {
	maxDelta := flag.Int("max-delta", 16, "largest positive or negative generator coordinate delta")
	output := flag.String("out", "testdata/curve-mutation-sweep.json", "serialized point corpus path")
	flag.Parse()

	doc, err := corpus.BuildCurveMutationSweep(*maxDelta)
	check(err)
	encoded, err := json.MarshalIndent(doc, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	check(os.WriteFile(*output, encoded, 0o644))
	fmt.Printf("wrote %d on-curve off-subgroup mutations to %s\n", len(doc.Cases), *output)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
