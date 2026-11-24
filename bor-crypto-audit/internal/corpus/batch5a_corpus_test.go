package corpus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"bor-crypto-audit/internal/reference"
)

func TestBatch5ACorpusDeterministicAndMathematicallyClassified(t *testing.T) {
	first, err := BuildBatch5ACorpus(Batch5ASeed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildBatch5ACorpus(Batch5ASeed)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("same Batch 5A seed produced a different corpus")
	}
	if first.Seed != Batch5ASeed || len(first.Cases) != 91 {
		t.Fatalf("unexpected corpus metadata: seed=%q cases=%d", first.Seed, len(first.Cases))
	}

	r := reference.SubgroupOrder()
	seenScalars := map[string]bool{}
	categoryCount := map[string]int{}
	for _, testCase := range first.Cases {
		categoryCount[testCase.Category]++
		if testCase.TupleCount != len(testCase.Tuples) {
			t.Errorf("%s: tuple_count=%d but has %d tuples", testCase.Name, testCase.TupleCount, len(testCase.Tuples))
		}
		sum := new(big.Int)
		for i, tuple := range testCase.Tuples {
			a := mustScalar(t, tuple.AScalarHex)
			b := mustScalar(t, tuple.BScalarHex)
			if a.Sign() < 0 || a.Cmp(r) >= 0 || b.Sign() < 0 || b.Cmp(r) >= 0 {
				t.Errorf("%s tuple %d has a scalar outside [0,r)", testCase.Name, i)
			}
			sum.Add(sum, new(big.Int).Mul(a, b)).Mod(sum, r)

			g1Bytes := mustEncoding(t, tuple.G1EncodingHex, 128)
			g2Bytes := mustEncoding(t, tuple.G2EncodingHex, 256)
			g1 := reference.G1Point{X: new(big.Int).SetBytes(g1Bytes[:64]), Y: new(big.Int).SetBytes(g1Bytes[64:]), Infinity: allZero(g1Bytes)}
			g2 := reference.G2Point{
				X:        reference.NewFp2(new(big.Int).SetBytes(g2Bytes[:64]), new(big.Int).SetBytes(g2Bytes[64:128])),
				Y:        reference.NewFp2(new(big.Int).SetBytes(g2Bytes[128:192]), new(big.Int).SetBytes(g2Bytes[192:])),
				Infinity: allZero(g2Bytes),
			}
			if !reference.G1OnCurve(g1) || !reference.G2OnCurve(g2) || !tuple.G1OnCurve || !tuple.G2OnCurve {
				t.Errorf("%s tuple %d contains an off-curve point", testCase.Name, i)
			}
			if !tuple.G1InSubgroup || !tuple.G2InSubgroup {
				t.Errorf("%s tuple %d was not independently marked in-subgroup", testCase.Name, i)
			}
			g1Key := "G1:" + tuple.AScalarHex
			g2Key := "G2:" + tuple.BScalarHex
			if !seenScalars[g1Key] {
				if !reference.G1InSubgroup(g1) {
					t.Errorf("%s tuple %d G1 fails independent [r]P=O", testCase.Name, i)
				}
				seenScalars[g1Key] = true
			}
			if !seenScalars[g2Key] {
				if !reference.G2InSubgroup(g2) {
					t.Errorf("%s tuple %d G2 fails independent [r]P=O", testCase.Name, i)
				}
				seenScalars[g2Key] = true
			}
		}
		want := mustScalar(t, testCase.ExpectedExponentHex)
		if sum.Cmp(want) != 0 || (sum.Sign() == 0) != testCase.ExpectedIdentity {
			t.Errorf("%s: scalar-product oracle mismatch: got %s, recorded %s identity=%v", testCase.Name, sum.Text(16), want.Text(16), testCase.ExpectedIdentity)
		}
		switch testCase.Category {
		case "random-identity", "exact-cancellation", "ordered-identity", "reordered-identity":
			if sum.Sign() != 0 {
				t.Errorf("%s: category requires an identity product, exponent is %s", testCase.Name, sum.Text(16))
			}
		case "random-nonidentity":
			if sum.Sign() == 0 {
				t.Errorf("%s: category requires a nonidentity product", testCase.Name)
			}
		case "near-identity":
			if sum.Cmp(big.NewInt(1)) != 0 && sum.Cmp(new(big.Int).Sub(r, big.NewInt(1))) != 0 {
				t.Errorf("%s: exponent %s is not 1 or r-1", testCase.Name, sum.Text(16))
			}
		}
	}
	for _, testCase := range first.Cases {
		if testCase.Category == "random-identity" && testCase.TupleCount >= 16 {
			unique := map[string]bool{}
			for _, tuple := range testCase.Tuples {
				unique[tuple.AScalarHex+":"+tuple.BScalarHex] = true
			}
			if len(unique) < 8 {
				t.Errorf("%s: random identity tuple scalars are insufficiently varied (%d unique pairs)", testCase.Name, len(unique))
			}
		}
	}
	for _, category := range []string{"random-identity", "random-nonidentity", "exact-cancellation", "near-identity", "reordered-identity", "repeated-pair", "infinity-mixed-with-ordinary", "boundary-scalars"} {
		if categoryCount[category] == 0 {
			t.Errorf("missing corpus category %q", category)
		}
	}
	for _, count := range []int{1, 2, 3, 8, 16, 32, 64, 127, 128, 129, 256} {
		if !hasCaseWithCount(first.Cases, "random-identity", count) || !hasCaseWithCount(first.Cases, "random-nonidentity", count) {
			t.Errorf("missing random identity/nonidentity cases at tuple count %d", count)
		}
	}
}

func mustScalar(t *testing.T, encoded string) *big.Int {
	t.Helper()
	value, ok := new(big.Int).SetString(encoded, 16)
	if !ok {
		t.Fatalf("invalid scalar hex %q", encoded)
	}
	return value
}

func mustEncoding(t *testing.T, encoded string, size int) []byte {
	t.Helper()
	value, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != size {
		t.Fatalf("encoded point has %d bytes, want %d", len(value), size)
	}
	return value
}

func hasCaseWithCount(cases []Batch5ACase, category string, count int) bool {
	for _, testCase := range cases {
		if testCase.Category == category && testCase.TupleCount == count {
			return true
		}
	}
	return false
}
