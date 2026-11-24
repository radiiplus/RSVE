package main

import (
	"flag"
	"fmt"
	"os"

	"bor-crypto-audit/internal/corpus"
)

func main() {
	output := flag.String("out", "testdata/bls12-381-corpus.json", "corpus output path")
	flag.Parse()

	encoded, err := corpus.Marshal()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
