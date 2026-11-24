package corpus

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"bor-crypto-audit/internal/reference"
)

const Seed = "bor-crypto-audit/bls12-381/corpus/v1"
const OffSubgroupSweepSeed = "bor-crypto-audit/bls12-381/off-subgroup-sweep/v1"
const CurveMutationSweepSeed = "bor-crypto-audit/bls12-381/curve-mutation-sweep/v1"

type Document struct {
	SchemaVersion int              `json:"schema_version"`
	Seed          string           `json:"seed"`
	PRNG          string           `json:"prng"`
	Parameters    ParameterSummary `json:"parameters"`
	Cases         []Case           `json:"cases"`
}

type ParameterSummary struct {
	BaseFieldModulus string `json:"base_field_modulus_hex"`
	SubgroupOrder    string `json:"subgroup_order_hex"`
	Fp2              string `json:"fp2_representation"`
}

type Case struct {
	Name           string         `json:"name"`
	Curve          string         `json:"curve"`
	Kind           string         `json:"kind"`
	Generation     string         `json:"generation"`
	ScalarHex      string         `json:"scalar_hex,omitempty"`
	ByteLength     int            `json:"byte_length"`
	EncodingHex    string         `json:"encoding_hex"`
	Classification Classification `json:"classification"`
}

type Classification struct {
	Label                   string `json:"label"`
	EncodedLengthValid      bool   `json:"encoded_length_valid"`
	CoordinateElementsValid *bool  `json:"coordinate_field_elements_canonical,omitempty"`
	OnCurve                 *bool  `json:"on_curve,omitempty"`
	InSubgroup              *bool  `json:"in_subgroup,omitempty"`
	Infinity                *bool  `json:"infinity,omitempty"`
}

func Build() (Document, error) {
	seed := []byte(Seed)
	rng := &counterStream{seed: seed}
	p := reference.BaseFieldModulus()
	r := reference.SubgroupOrder()
	doc := Document{
		SchemaVersion: 1,
		Seed:          Seed,
		PRNG:          "SHA-256 counter stream; each block is SHA256(seed || uint64_be(counter)); candidates are reduced modulo p or r",
		Parameters: ParameterSummary{
			BaseFieldModulus: p.Text(16),
			SubgroupOrder:    r.Text(16),
			Fp2:              "c0 + c1*i, i^2 = -1; G2 coordinates serialize x.c0 || x.c1 || y.c0 || y.c1",
		},
	}

	boundaries := []struct {
		name  string
		value *big.Int
	}{
		{name: "zero", value: new(big.Int)},
		{name: "one", value: big.NewInt(1)},
		{name: "p-minus-1", value: new(big.Int).Sub(p, big.NewInt(1))},
		{name: "p", value: new(big.Int).Set(p)},
		{name: "p-plus-1", value: new(big.Int).Add(p, big.NewInt(1))},
		{name: "max-384-bit", value: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 384), big.NewInt(1))},
	}
	for _, boundary := range boundaries {
		encoded := encodeField(boundary.value)
		doc.Cases = append(doc.Cases, Case{
			Name:           "field-" + boundary.name,
			Curve:          "Fp",
			Kind:           "field-element",
			Generation:     "fixed canonical-encoding boundary",
			ByteLength:     len(encoded),
			EncodingHex:    hex.EncodeToString(encoded),
			Classification: classifyField(encoded),
		})
	}

	leadingBytes := make([]byte, 64)
	leadingBytes[0] = 1
	doc.Cases = append(doc.Cases, Case{
		Name: "field-nonzero-leading-16-bytes", Curve: "Fp", Kind: "field-element",
		Generation: "fixed malformed encoding; first of the 16 required zero bytes is nonzero",
		ByteLength: len(leadingBytes), EncodingHex: hex.EncodeToString(leadingBytes),
		Classification: classifyField(leadingBytes),
	})
	for _, length := range []int{0, 63, 65} {
		encoded := make([]byte, length)
		doc.Cases = append(doc.Cases, Case{
			Name: fmt.Sprintf("field-invalid-length-%d", length), Curve: "Fp", Kind: "field-element",
			Generation: "fixed malformed field-element length", ByteLength: len(encoded), EncodingHex: hex.EncodeToString(encoded),
			Classification: Classification{Label: "malformed-field-length", EncodedLengthValid: false},
		})
	}

	g1 := reference.G1Generator()
	g2 := reference.G2Generator()
	for _, boundary := range boundaries {
		p1 := reference.G1Point{X: boundary.value, Y: g1.Y}
		doc.Cases = appendPoint(doc.Cases, "g1-x-"+boundary.name, "G1", "fixed point coordinate boundary", encodeG1(p1))
		g2Boundary := encodeG2Coordinates(boundary.value, g2.X.C1, g2.Y.C0, g2.Y.C1)
		doc.Cases = appendPoint(doc.Cases, "g2-x-c0-"+boundary.name, "G2", "fixed point coordinate boundary", g2Boundary)
	}

	for _, length := range []int{127, 129} {
		encoded := resize(encodeG1(g1), length)
		doc.Cases = appendPoint(doc.Cases, fmt.Sprintf("g1-invalid-point-length-%d", length), "G1", "fixed malformed point length", encoded)
	}
	for _, length := range []int{255, 257} {
		encoded := resize(encodeG2(g2), length)
		doc.Cases = appendPoint(doc.Cases, fmt.Sprintf("g2-invalid-point-length-%d", length), "G2", "fixed malformed point length", encoded)
	}

	for _, point := range []struct {
		name string
		p    reference.G1Point
	}{
		{name: "g1-degenerate-zero-one", p: reference.G1Point{X: new(big.Int), Y: big.NewInt(1)}},
		{name: "g1-degenerate-one-zero", p: reference.G1Point{X: big.NewInt(1), Y: new(big.Int)}},
	} {
		doc.Cases = appendPoint(doc.Cases, point.name, "G1", "fixed degenerate coordinate combination", encodeG1(point.p))
	}
	for _, point := range []struct {
		name string
		p    reference.G2Point
	}{
		{name: "g2-degenerate-zero-one", p: reference.G2Point{X: reference.NewFp2(new(big.Int), new(big.Int)), Y: reference.NewFp2(big.NewInt(1), new(big.Int))}},
		{name: "g2-degenerate-one-zero", p: reference.G2Point{X: reference.NewFp2(big.NewInt(1), new(big.Int)), Y: reference.NewFp2(new(big.Int), new(big.Int))}},
	} {
		doc.Cases = appendPoint(doc.Cases, point.name, "G2", "fixed degenerate coordinate combination", encodeG2(point.p))
	}

	doc.Cases = appendPoint(doc.Cases, "g1-canonical-infinity", "G1", "EIP-2537 all-zero infinity encoding", make([]byte, 128))
	doc.Cases = appendPoint(doc.Cases, "g2-canonical-infinity", "G2", "EIP-2537 all-zero infinity encoding", make([]byte, 256))

	doc.Cases = appendPoint(doc.Cases, "g1-standard-generator", "G1", "EIP-2537 standard generator", encodeG1(g1))
	doc.Cases = appendPoint(doc.Cases, "g2-standard-generator", "G2", "EIP-2537 standard generator", encodeG2(g2))
	for _, scalar := range []*big.Int{new(big.Int), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(7), new(big.Int).Sub(r, big.NewInt(1)), nextScalar(rng, r)} {
		name := "scalar-" + scalar.Text(16)
		doc.Cases = appendPointWithScalar(doc.Cases, "g1-generator-"+name, "G1", scalar, encodeG1(reference.G1ScalarMult(g1, scalar)))
		doc.Cases = appendPointWithScalar(doc.Cases, "g2-generator-"+name, "G2", scalar, encodeG2(reference.G2ScalarMult(g2, scalar)))
	}

	doc.Cases = appendPoint(doc.Cases, "g2-swap-x-coefficients", "G2", "swap x.c0 and x.c1 in standard generator encoding", encodeG2(reference.G2Point{
		X: reference.NewFp2(g2.X.C1, g2.X.C0), Y: g2.Y,
	}))
	doc.Cases = appendPoint(doc.Cases, "g2-swap-y-coefficients", "G2", "swap y.c0 and y.c1 in standard generator encoding", encodeG2(reference.G2Point{
		X: g2.X, Y: reference.NewFp2(g2.Y.C1, g2.Y.C0),
	}))
	doc.Cases = appendPoint(doc.Cases, "g2-reverse-coefficients", "G2", "swap c0 and c1 in both G2 coordinates", encodeG2(reference.G2Point{
		X: reference.NewFp2(g2.X.C1, g2.X.C0), Y: reference.NewFp2(g2.Y.C1, g2.Y.C0),
	}))
	doc.Cases = appendPoint(doc.Cases, "g2-swap-x-and-y", "G2", "swap encoded Fp2 x and y coordinates", encodeG2(reference.G2Point{X: g2.Y, Y: g2.X}))

	if err := appendRandomOffSubgroup(&doc, rng); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func BuildOffSubgroupSweep(countPerGroup int) (Document, error) {
	if countPerGroup <= 0 {
		return Document{}, fmt.Errorf("sample count must be positive")
	}
	rng := &counterStream{seed: []byte(OffSubgroupSweepSeed)}
	p := reference.BaseFieldModulus()
	doc := Document{
		SchemaVersion: 1,
		Seed:          OffSubgroupSweepSeed,
		PRNG:          "SHA-256 counter stream; candidate x-coordinates are sampled modulo p and each y is recovered by a square-root check",
		Parameters: ParameterSummary{
			BaseFieldModulus: p.Text(16),
			SubgroupOrder:    reference.SubgroupOrder().Text(16),
			Fp2:              "c0 + c1*i, i^2 = -1; G2 coordinates serialize x.c0 || x.c1 || y.c0 || y.c1",
		},
	}

	g1Found := 0
	for attempt := 0; g1Found < countPerGroup && attempt < countPerGroup*10000; attempt++ {
		x := rng.nextInt(p)
		rhs := reference.FpAdd(reference.FpMul(reference.FpMul(x, x), x), big.NewInt(4))
		y, ok := sqrtFp(rhs)
		if !ok {
			continue
		}
		if rng.nextInt(big.NewInt(2)).Sign() != 0 {
			y = reference.FpSub(new(big.Int), y)
		}
		point := reference.G1Point{X: x, Y: y}
		if !reference.G1OnCurve(point) || reference.G1InSubgroup(point) {
			continue
		}
		name := fmt.Sprintf("sweep-g1-%04d-attempt-%d", g1Found, attempt)
		doc.Cases = append(doc.Cases, Case{
			Name: name, Curve: "G1", Kind: "point",
			Generation: "direct full-curve sample: deterministic x, square root of x^3+4, retained only when independent [r]P is not infinity",
			ByteLength: 128, EncodingHex: hex.EncodeToString(encodeG1(point)),
			Classification: pointClassification("on-curve-outside-subgroup", true, false, false),
		})
		g1Found++
	}
	if g1Found != countPerGroup {
		return Document{}, fmt.Errorf("generated %d of %d G1 off-subgroup samples", g1Found, countPerGroup)
	}

	g2Found := 0
	b := reference.NewFp2(big.NewInt(4), big.NewInt(4))
	for attempt := 0; g2Found < countPerGroup && attempt < countPerGroup*10000; attempt++ {
		x := reference.NewFp2(rng.nextInt(p), rng.nextInt(p))
		rhs := reference.Fp2Add(reference.Fp2Mul(reference.Fp2Mul(x, x), x), b)
		y, ok := sqrtFp2(rhs)
		if !ok {
			continue
		}
		if rng.nextInt(big.NewInt(2)).Sign() != 0 {
			y = reference.Fp2Sub(reference.NewFp2(new(big.Int), new(big.Int)), y)
		}
		point := reference.G2Point{X: x, Y: y}
		if !reference.G2OnCurve(point) || reference.G2InSubgroup(point) {
			continue
		}
		name := fmt.Sprintf("sweep-g2-%04d-attempt-%d", g2Found, attempt)
		doc.Cases = append(doc.Cases, Case{
			Name: name, Curve: "G2", Kind: "point",
			Generation: "direct full-curve sample: deterministic x, Fp2 square root of x^3+4(1+i), retained only when independent [r]P is not infinity",
			ByteLength: 256, EncodingHex: hex.EncodeToString(encodeG2(point)),
			Classification: pointClassification("on-curve-outside-subgroup", true, false, false),
		})
		g2Found++
	}
	if g2Found != countPerGroup {
		return Document{}, fmt.Errorf("generated %d of %d G2 off-subgroup samples", g2Found, countPerGroup)
	}
	return doc, nil
}

// BuildCurveMutationSweep perturbs generator x-coordinate components by each
// signed delta in [1,maxDelta], recovers curve y-coordinates, and keeps points
// whose ordinary [r]P calculation places them outside the intended subgroup.
func BuildCurveMutationSweep(maxDelta int) (Document, error) {
	if maxDelta <= 0 {
		return Document{}, fmt.Errorf("maximum coordinate delta must be positive")
	}
	p := reference.BaseFieldModulus()
	doc := Document{
		SchemaVersion: 1,
		Seed:          CurveMutationSweepSeed,
		PRNG:          "deterministic signed integer deltas applied to standard generator x-coordinate components; y is recovered by field square roots",
		Parameters: ParameterSummary{
			BaseFieldModulus: p.Text(16),
			SubgroupOrder:    reference.SubgroupOrder().Text(16),
			Fp2:              "c0 + c1*i, i^2 = -1; G2 coordinates serialize x.c0 || x.c1 || y.c0 || y.c1",
		},
	}
	g1Generator := reference.G1Generator()
	for delta := 1; delta <= maxDelta; delta++ {
		for _, signedDelta := range []int{-delta, delta} {
			x := reference.FpAdd(g1Generator.X, big.NewInt(int64(signedDelta)))
			rhs := reference.FpAdd(reference.FpMul(reference.FpMul(x, x), x), big.NewInt(4))
			y, ok := sqrtFp(rhs)
			if !ok {
				continue
			}
			for rootIndex, root := range []*big.Int{y, reference.FpSub(new(big.Int), y)} {
				point := reference.G1Point{X: x, Y: root}
				if !reference.G1OnCurve(point) || reference.G1InSubgroup(point) {
					continue
				}
				name := fmt.Sprintf("mutation-g1-delta-%+d-root-%d", signedDelta, rootIndex)
				doc.Cases = appendPoint(doc.Cases, name, "G1", "generator x-coordinate plus signed small delta; y recovered from x^3+4; classified by ordinary [r]P", encodeG1(point))
			}
		}
	}
	g2Generator := reference.G2Generator()
	b := reference.NewFp2(big.NewInt(4), big.NewInt(4))
	for component := 0; component < 2; component++ {
		for delta := 1; delta <= maxDelta; delta++ {
			for _, signedDelta := range []int{-delta, delta} {
				x := reference.NewFp2(g2Generator.X.C0, g2Generator.X.C1)
				if component == 0 {
					x.C0 = reference.FpAdd(x.C0, big.NewInt(int64(signedDelta)))
				} else {
					x.C1 = reference.FpAdd(x.C1, big.NewInt(int64(signedDelta)))
				}
				rhs := reference.Fp2Add(reference.Fp2Mul(reference.Fp2Mul(x, x), x), b)
				y, ok := sqrtFp2(rhs)
				if !ok {
					continue
				}
				for rootIndex, root := range []reference.Fp2{y, reference.Fp2Sub(reference.NewFp2(new(big.Int), new(big.Int)), y)} {
					point := reference.G2Point{X: x, Y: root}
					if !reference.G2OnCurve(point) || reference.G2InSubgroup(point) {
						continue
					}
					name := fmt.Sprintf("mutation-g2-x-c%d-delta-%+d-root-%d", component, signedDelta, rootIndex)
					doc.Cases = appendPoint(doc.Cases, name, "G2", fmt.Sprintf("generator x.c%d plus signed small delta; y recovered from x^3+4(1+i); classified by ordinary [r]P", component), encodeG2(point))
				}
			}
		}
	}
	if len(doc.Cases) == 0 {
		return Document{}, fmt.Errorf("no on-curve off-subgroup mutation samples generated")
	}
	return doc, nil
}

func Marshal() ([]byte, error) {
	doc, err := Build()
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func appendPoint(cases []Case, name, curve, generation string, encoded []byte) []Case {
	return append(cases, Case{
		Name: name, Curve: curve, Kind: "point", Generation: generation,
		ByteLength: len(encoded), EncodingHex: hex.EncodeToString(encoded),
		Classification: classifyPoint(curve, encoded),
	})
}

func appendPointWithScalar(cases []Case, name, curve string, scalar *big.Int, encoded []byte) []Case {
	cases = appendPoint(cases, name, curve, "ordinary scalar multiple of standard generator", encoded)
	cases[len(cases)-1].ScalarHex = scalar.Text(16)
	return cases
}

func classifyField(encoded []byte) Classification {
	if len(encoded) != 64 {
		return Classification{Label: "malformed-field-length", EncodedLengthValid: false}
	}
	v := new(big.Int).SetBytes(encoded)
	canonical := v.Cmp(reference.BaseFieldModulus()) < 0
	label := "canonical-field-element"
	if !canonical {
		label = "noncanonical-field-element"
	}
	return Classification{Label: label, EncodedLengthValid: true, CoordinateElementsValid: boolPointer(canonical)}
}

func classifyPoint(curve string, encoded []byte) Classification {
	width := 128
	fieldCount := 2
	if curve == "G2" {
		width, fieldCount = 256, 4
	}
	if len(encoded) != width {
		return Classification{Label: "malformed-point-length", EncodedLengthValid: false}
	}
	if allZero(encoded) {
		return Classification{
			Label: "canonical-infinity", EncodedLengthValid: true,
			CoordinateElementsValid: boolPointer(true), OnCurve: boolPointer(true),
			InSubgroup: boolPointer(true), Infinity: boolPointer(true),
		}
	}
	values := make([]*big.Int, fieldCount)
	canonical := true
	p := reference.BaseFieldModulus()
	for i := range values {
		values[i] = new(big.Int).SetBytes(encoded[i*64 : (i+1)*64])
		if values[i].Cmp(p) >= 0 {
			canonical = false
		}
	}
	if !canonical {
		return Classification{
			Label: "noncanonical-coordinate-field-element", EncodedLengthValid: true,
			CoordinateElementsValid: boolPointer(false), OnCurve: boolPointer(false),
			InSubgroup: boolPointer(false), Infinity: boolPointer(false),
		}
	}
	if curve == "G1" {
		point := reference.G1Point{X: values[0], Y: values[1]}
		onCurve := reference.G1OnCurve(point)
		if !onCurve {
			return pointClassification("off-curve", false, false, false)
		}
		inSubgroup := reference.G1InSubgroup(point)
		label := "on-curve-outside-subgroup"
		if inSubgroup {
			label = "on-curve-subgroup"
		}
		return pointClassification(label, true, inSubgroup, false)
	}
	point := reference.G2Point{
		X: reference.NewFp2(values[0], values[1]),
		Y: reference.NewFp2(values[2], values[3]),
	}
	onCurve := reference.G2OnCurve(point)
	if !onCurve {
		return pointClassification("off-curve", false, false, false)
	}
	inSubgroup := reference.G2InSubgroup(point)
	label := "on-curve-outside-subgroup"
	if inSubgroup {
		label = "on-curve-subgroup"
	}
	return pointClassification(label, true, inSubgroup, false)
}

func pointClassification(label string, onCurve, inSubgroup, infinity bool) Classification {
	return Classification{
		Label: label, EncodedLengthValid: true,
		CoordinateElementsValid: boolPointer(true), OnCurve: boolPointer(onCurve),
		InSubgroup: boolPointer(inSubgroup), Infinity: boolPointer(infinity),
	}
}

func appendRandomOffSubgroup(doc *Document, rng *counterStream) error {
	g1Found := false
	for attempt := 0; attempt < 10000; attempt++ {
		x := rng.nextInt(reference.BaseFieldModulus())
		rhs := reference.FpAdd(reference.FpMul(reference.FpMul(x, x), x), big.NewInt(4))
		y, ok := sqrtFp(rhs)
		if !ok {
			continue
		}
		if rng.nextInt(big.NewInt(2)).Sign() != 0 {
			y = reference.FpSub(new(big.Int), y)
		}
		point := reference.G1Point{X: x, Y: y}
		if !reference.G1InSubgroup(point) {
			encoded := encodeG1(point)
			name := fmt.Sprintf("g1-deterministic-full-curve-sample-%d", attempt)
			doc.Cases = appendPoint(doc.Cases, name, "G1", "SHA-256 deterministic x sampling; square root of x^3+4; subgroup classified by [r]P", encoded)
			g1Found = true
			break
		}
	}
	if !g1Found {
		return fmt.Errorf("failed to find deterministic G1 off-subgroup sample")
	}

	b := reference.NewFp2(big.NewInt(4), big.NewInt(4))
	g2Found := false
	for attempt := 0; attempt < 10000; attempt++ {
		x := reference.NewFp2(rng.nextInt(reference.BaseFieldModulus()), rng.nextInt(reference.BaseFieldModulus()))
		rhs := reference.Fp2Add(reference.Fp2Mul(reference.Fp2Mul(x, x), x), b)
		y, ok := sqrtFp2(rhs)
		if !ok {
			continue
		}
		if rng.nextInt(big.NewInt(2)).Sign() != 0 {
			y = reference.Fp2Sub(reference.NewFp2(new(big.Int), new(big.Int)), y)
		}
		point := reference.G2Point{X: x, Y: y}
		if !reference.G2InSubgroup(point) {
			encoded := encodeG2(point)
			name := fmt.Sprintf("g2-deterministic-full-curve-sample-%d", attempt)
			doc.Cases = appendPoint(doc.Cases, name, "G2", "SHA-256 deterministic x sampling; Fp2 square root of x^3+4(1+i); subgroup classified by [r]P", encoded)
			g2Found = true
			break
		}
	}
	if !g2Found {
		return fmt.Errorf("failed to find deterministic G2 off-subgroup sample")
	}
	return nil
}

func sqrtFp(n *big.Int) (*big.Int, bool) {
	p := reference.BaseFieldModulus()
	n = new(big.Int).Mod(n, p)
	if n.Sign() == 0 {
		return new(big.Int), true
	}
	exponent := new(big.Int).Add(p, big.NewInt(1))
	exponent.Rsh(exponent, 2)
	root := new(big.Int).Exp(n, exponent, p)
	if reference.FpMul(root, root).Cmp(n) != 0 {
		return nil, false
	}
	return root, true
}

func sqrtFp2(n reference.Fp2) (reference.Fp2, bool) {
	zero := new(big.Int)
	if n.C1.Sign() == 0 {
		if root, ok := sqrtFp(n.C0); ok {
			return reference.NewFp2(root, zero), true
		}
		minusC0 := reference.FpSub(zero, n.C0)
		if root, ok := sqrtFp(minusC0); ok {
			return reference.NewFp2(zero, root), true
		}
		return reference.Fp2{}, false
	}

	norm := reference.FpAdd(reference.FpMul(n.C0, n.C0), reference.FpMul(n.C1, n.C1))
	delta, ok := sqrtFp(norm)
	if !ok {
		return reference.Fp2{}, false
	}
	twoInv := reference.FpInverse(big.NewInt(2))
	for _, d := range []*big.Int{delta, reference.FpSub(zero, delta)} {
		xSquared := reference.FpMul(reference.FpAdd(n.C0, d), twoInv)
		x, square := sqrtFp(xSquared)
		if !square || x.Sign() == 0 {
			continue
		}
		y := reference.FpMul(n.C1, reference.FpInverse(reference.FpMul(big.NewInt(2), x)))
		root := reference.NewFp2(x, y)
		if reference.Fp2Equal(reference.Fp2Mul(root, root), n) {
			return root, true
		}
	}
	return reference.Fp2{}, false
}

func encodeG1(p reference.G1Point) []byte {
	out := make([]byte, 128)
	if p.Infinity {
		return out
	}
	copy(out[:64], encodeField(p.X))
	copy(out[64:], encodeField(p.Y))
	return out
}

func encodeG2(p reference.G2Point) []byte {
	out := make([]byte, 256)
	if p.Infinity {
		return out
	}
	copy(out[0:64], encodeField(p.X.C0))
	copy(out[64:128], encodeField(p.X.C1))
	copy(out[128:192], encodeField(p.Y.C0))
	copy(out[192:256], encodeField(p.Y.C1))
	return out
}

func encodeG2Coordinates(x0, x1, y0, y1 *big.Int) []byte {
	out := make([]byte, 256)
	copy(out[0:64], encodeField(x0))
	copy(out[64:128], encodeField(x1))
	copy(out[128:192], encodeField(y0))
	copy(out[192:256], encodeField(y1))
	return out
}

func encodeField(n *big.Int) []byte {
	encoded := n.Bytes()
	if len(encoded) > 64 {
		panic("field encoding exceeds 64 bytes")
	}
	out := make([]byte, 64)
	copy(out[len(out)-len(encoded):], encoded)
	return out
}

func resize(input []byte, size int) []byte {
	out := make([]byte, size)
	copy(out, input)
	return out
}

func allZero(input []byte) bool {
	for _, b := range input {
		if b != 0 {
			return false
		}
	}
	return true
}

func boolPointer(v bool) *bool { return &v }

func nextScalar(rng *counterStream, modulus *big.Int) *big.Int {
	s := rng.nextInt(modulus)
	if s.Sign() == 0 {
		return big.NewInt(1)
	}
	return s
}

type counterStream struct {
	seed    []byte
	counter uint64
}

func (r *counterStream) nextBlock() []byte {
	data := make([]byte, len(r.seed)+8)
	copy(data, r.seed)
	binary.BigEndian.PutUint64(data[len(r.seed):], r.counter)
	r.counter++
	h := sha256.Sum256(data)
	return h[:]
}

func (r *counterStream) nextInt(modulus *big.Int) *big.Int {
	wide := append(r.nextBlock(), r.nextBlock()...)
	return new(big.Int).Mod(new(big.Int).SetBytes(wide), modulus)
}
