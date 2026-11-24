package corpus

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"bor-crypto-audit/internal/reference"
)

const Batch5ASeed = "bor-crypto-audit/bls12-381/batch5a-pairing-products/v1"

type Batch5ACorpus struct {
	SchemaVersion    int           `json:"schema_version"`
	Seed             string        `json:"seed"`
	PRNG             string        `json:"prng"`
	SubgroupOrderHex string        `json:"subgroup_order_hex"`
	Cases            []Batch5ACase `json:"cases"`
}

type Batch5ACase struct {
	Name                string         `json:"name"`
	Category            string         `json:"category"`
	Seed                string         `json:"seed"`
	TupleCount          int            `json:"tuple_count"`
	ExpectedExponentHex string         `json:"expected_exponent_hex"`
	ExpectedIdentity    bool           `json:"expected_identity"`
	Tuples              []Batch5ATuple `json:"tuples"`
}

type Batch5ATuple struct {
	AScalarHex    string `json:"a_scalar_hex"`
	BScalarHex    string `json:"b_scalar_hex"`
	G1EncodingHex string `json:"g1_encoding_hex"`
	G2EncodingHex string `json:"g2_encoding_hex"`
	G1OnCurve     bool   `json:"g1_on_curve"`
	G1InSubgroup  bool   `json:"g1_in_subgroup"`
	G2OnCurve     bool   `json:"g2_on_curve"`
	G2InSubgroup  bool   `json:"g2_in_subgroup"`
}

type scalarPair struct {
	a, b *big.Int
}

// BuildBatch5ACorpus creates valid subgroup points from the independent
// reference generators. Expected identity is computed only as sum(a_i*b_i)
// modulo r, using the nondegenerate bilinear pairing equation.
func BuildBatch5ACorpus(seed string) (Batch5ACorpus, error) {
	if seed == "" {
		return Batch5ACorpus{}, fmt.Errorf("seed must not be empty")
	}
	r := reference.SubgroupOrder()
	c := Batch5ACorpus{
		SchemaVersion:    1,
		Seed:             seed,
		PRNG:             "SHA-256 counter stream derives a 64-scalar nonzero pool from seed || /scalar-pool; per-case streams independently select from the pool; expected exponents are reduced modulo r",
		SubgroupOrderHex: r.Text(16),
		Cases:            make([]Batch5ACase, 0),
	}
	pointCache := newBatch5APointCache()
	pool := randomScalarPool(seed+"/scalar-pool", r, 64)

	counts := []int{1, 2, 3, 8, 16, 32, 64, 127, 128, 129, 256}
	for _, count := range counts {
		caseSeed := seed + "/random-identity-" + fmt.Sprint(count)
		rng := &counterStream{seed: []byte(caseSeed)}
		pairs := randomIdentityPairs(count, rng, pool, r)
		c.Cases = append(c.Cases, pointProductCase("random-identity-"+fmt.Sprint(count), "random-identity", caseSeed, pairs, r, pointCache))

		caseSeed = seed + "/random-nonidentity-" + fmt.Sprint(count)
		rng = &counterStream{seed: []byte(caseSeed)}
		pairs = randomNonidentityPairs(count, rng, pool, r)
		c.Cases = append(c.Cases, pointProductCase("random-nonidentity-"+fmt.Sprint(count), "random-nonidentity", caseSeed, pairs, r, pointCache))
	}

	for _, count := range []int{1, 2, 3, 8, 16, 32, 64, 127, 128, 129, 256} {
		caseSeed := seed + "/exact-cancellation-" + fmt.Sprint(count)
		pairs := cancellationPairs(count, big.NewInt(17), big.NewInt(23), r)
		c.Cases = append(c.Cases, pointProductCase("exact-cancellation-"+fmt.Sprint(count), "exact-cancellation", caseSeed, pairs, r, pointCache))
	}

	for _, count := range []int{1, 2, 3, 8, 16, 32, 64, 127, 128, 129, 256} {
		for _, target := range []*big.Int{big.NewInt(1), new(big.Int).Sub(r, big.NewInt(1))} {
			caseSeed := fmt.Sprintf("%s/near-identity-%d-%s", seed, count, target.Text(16))
			pairs := exponentPairs(count, big.NewInt(17), big.NewInt(23), target, r)
			c.Cases = append(c.Cases, pointProductCase(fmt.Sprintf("near-identity-%d-%s", count, target.Text(16)), "near-identity", caseSeed, pairs, r, pointCache))
		}
	}

	for _, count := range []int{3, 8, 129} {
		caseSeed := seed + "/reordered-identity-" + fmt.Sprint(count)
		pairs := randomIdentityPairs(count, &counterStream{seed: []byte(caseSeed)}, pool, r)
		original := pointProductCase("ordered-identity-"+fmt.Sprint(count), "ordered-identity", caseSeed, pairs, r, pointCache)
		c.Cases = append(c.Cases, original)
		reversed := append([]scalarPair(nil), pairs...)
		for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
			reversed[i], reversed[j] = reversed[j], reversed[i]
		}
		c.Cases = append(c.Cases, pointProductCase("reordered-identity-"+fmt.Sprint(count), "reordered-identity", caseSeed+"/reverse", reversed, r, pointCache))
	}

	for _, count := range counts {
		caseSeed := seed + "/repeated-pair-" + fmt.Sprint(count)
		pairs := make([]scalarPair, count)
		for i := range pairs {
			pairs[i] = scalarPair{a: big.NewInt(5), b: big.NewInt(7)}
		}
		c.Cases = append(c.Cases, pointProductCase("repeated-pair-"+fmt.Sprint(count), "repeated-pair", caseSeed, pairs, r, pointCache))
	}

	for _, count := range []int{3, 8, 129} {
		caseSeed := seed + "/infinity-mixed-" + fmt.Sprint(count)
		pairs := make([]scalarPair, count)
		pairs[0] = scalarPair{a: new(big.Int), b: big.NewInt(11)}
		pairs[1] = scalarPair{a: big.NewInt(13), b: new(big.Int)}
		for i := 2; i < count; i++ {
			pairs[i] = scalarPair{a: big.NewInt(17), b: big.NewInt(19)}
		}
		c.Cases = append(c.Cases, pointProductCase("infinity-mixed-"+fmt.Sprint(count), "infinity-mixed-with-ordinary", caseSeed, pairs, r, pointCache))
	}

	boundary := []*big.Int{
		new(big.Int),
		big.NewInt(1),
		new(big.Int).Sub(r, big.NewInt(2)),
		new(big.Int).Sub(r, big.NewInt(1)),
	}
	for i, a := range boundary {
		for j, b := range boundary {
			caseSeed := fmt.Sprintf("%s/boundary-a%d-b%d", seed, i, j)
			pairs := []scalarPair{{a: new(big.Int).Set(a), b: new(big.Int).Set(b)}}
			c.Cases = append(c.Cases, pointProductCase(fmt.Sprintf("boundary-scalars-a%d-b%d", i, j), "boundary-scalars", caseSeed, pairs, r, pointCache))
		}
	}

	return c, nil
}

func randomIdentityPairs(count int, rng *counterStream, pool []*big.Int, r *big.Int) []scalarPair {
	pairs := make([]scalarPair, count)
	sum := new(big.Int)
	for i := 0; i < count-1; i++ {
		a := selectPoolScalar(rng, pool)
		b := selectPoolScalar(rng, pool)
		pairs[i] = scalarPair{a: a, b: b}
		sum.Add(sum, new(big.Int).Mul(a, b)).Mod(sum, r)
	}
	pairs[count-1] = scalarPair{a: big.NewInt(1), b: new(big.Int).Neg(sum)}
	return pairs
}

func randomNonidentityPairs(count int, rng *counterStream, pool []*big.Int, r *big.Int) []scalarPair {
	pairs := make([]scalarPair, count)
	sum := new(big.Int)
	for i := range pairs {
		a := selectPoolScalar(rng, pool)
		b := selectPoolScalar(rng, pool)
		pairs[i] = scalarPair{a: new(big.Int).Set(a), b: new(big.Int).Set(b)}
		sum.Add(sum, new(big.Int).Mul(a, b)).Mod(sum, r)
	}
	if sum.Sign() == 0 {
		last := &pairs[count-1]
		if last.a.Sign() == 0 {
			last.a = big.NewInt(1)
			last.b = big.NewInt(1)
		} else {
			last.b.Add(last.b, big.NewInt(1)).Mod(last.b, r)
		}
	}
	return pairs
}

func randomScalarPool(seed string, r *big.Int, size int) []*big.Int {
	rng := &counterStream{seed: []byte(seed)}
	pool := make([]*big.Int, 0, size)
	seen := make(map[string]bool, size)
	for len(pool) < size {
		scalar := rng.nextInt(r)
		key := scalar.Text(16)
		if scalar.Sign() == 0 || seen[key] {
			continue
		}
		seen[key] = true
		pool = append(pool, scalar)
	}
	return pool
}

func selectPoolScalar(rng *counterStream, pool []*big.Int) *big.Int {
	index := rng.nextInt(big.NewInt(int64(len(pool)))).Int64()
	return new(big.Int).Set(pool[index])
}

func cancellationPairs(count int, a, b, r *big.Int) []scalarPair {
	pairs := make([]scalarPair, count)
	for i := range pairs {
		if i == count-1 && count%2 != 0 {
			pairs[i] = scalarPair{a: new(big.Int), b: big.NewInt(1)}
		} else if i%2 == 0 {
			pairs[i] = scalarPair{a: new(big.Int).Set(a), b: new(big.Int).Set(b)}
		} else {
			pairs[i] = scalarPair{a: new(big.Int).Neg(a), b: new(big.Int).Set(b)}
		}
	}
	return pairs
}

func exponentPairs(count int, a, b, target, r *big.Int) []scalarPair {
	pairs := make([]scalarPair, count)
	if count == 1 {
		return []scalarPair{{a: big.NewInt(1), b: new(big.Int).Set(target)}}
	}
	fill := cancellationPairs(count-1, a, b, r)
	copy(pairs, fill)
	pairs[count-1] = scalarPair{a: big.NewInt(1), b: new(big.Int).Set(target)}
	return pairs
}

func pointProductCase(name, category, seed string, pairs []scalarPair, r *big.Int, cache *batch5APointCache) Batch5ACase {
	exponent := new(big.Int)
	tuples := make([]Batch5ATuple, len(pairs))
	for i, pair := range pairs {
		a := new(big.Int).Mod(new(big.Int).Set(pair.a), r)
		b := new(big.Int).Mod(new(big.Int).Set(pair.b), r)
		exponent.Add(exponent, new(big.Int).Mul(a, b)).Mod(exponent, r)
		g1 := cache.g1(a)
		g2 := cache.g2(b)
		tuples[i] = Batch5ATuple{
			AScalarHex: a.Text(16), BScalarHex: b.Text(16),
			G1EncodingHex: hex.EncodeToString(encodeG1(g1.point)), G2EncodingHex: hex.EncodeToString(encodeG2(g2.point)),
			G1OnCurve: g1.onCurve, G1InSubgroup: g1.inSubgroup,
			G2OnCurve: g2.onCurve, G2InSubgroup: g2.inSubgroup,
		}
	}
	return Batch5ACase{
		Name: name, Category: category, Seed: seed, TupleCount: len(tuples),
		ExpectedExponentHex: exponent.Text(16), ExpectedIdentity: exponent.Sign() == 0,
		Tuples: tuples,
	}
}

type batch5APointCache struct {
	g1Generator reference.G1Point
	g2Generator reference.G2Point
	g1Points    map[string]cachedBatch5AG1
	g2Points    map[string]cachedBatch5AG2
}

type cachedBatch5AG1 struct {
	point               reference.G1Point
	onCurve, inSubgroup bool
}

type cachedBatch5AG2 struct {
	point               reference.G2Point
	onCurve, inSubgroup bool
}

func newBatch5APointCache() *batch5APointCache {
	return &batch5APointCache{
		g1Generator: reference.G1Generator(), g2Generator: reference.G2Generator(),
		g1Points: make(map[string]cachedBatch5AG1), g2Points: make(map[string]cachedBatch5AG2),
	}
}

func (c *batch5APointCache) g1(scalar *big.Int) cachedBatch5AG1 {
	key := scalar.Text(16)
	if point, ok := c.g1Points[key]; ok {
		return point
	}
	point := reference.G1ScalarMult(c.g1Generator, scalar)
	classified := cachedBatch5AG1{point: point, onCurve: reference.G1OnCurve(point), inSubgroup: reference.G1InSubgroup(point)}
	c.g1Points[key] = classified
	return classified
}

func (c *batch5APointCache) g2(scalar *big.Int) cachedBatch5AG2 {
	key := scalar.Text(16)
	if point, ok := c.g2Points[key]; ok {
		return point
	}
	point := reference.G2ScalarMult(c.g2Generator, scalar)
	classified := cachedBatch5AG2{point: point, onCurve: reference.G2OnCurve(point), inSubgroup: reference.G2InSubgroup(point)}
	c.g2Points[key] = classified
	return classified
}
