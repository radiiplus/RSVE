package reference

import "math/big"

const (
	baseFieldHex = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
	orderHex     = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
	fp2NRHex     = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa"

	g1GeneratorXHex  = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
	g1GeneratorYHex  = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
	g2GeneratorX0Hex = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
	g2GeneratorX1Hex = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
	g2GeneratorY0Hex = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
	g2GeneratorY1Hex = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
)

var (
	pModulus = mustHex(baseFieldHex)
	rOrder   = mustHex(orderHex)
	nr2      = mustHex(fp2NRHex)
)

type Fp2 struct {
	C0 *big.Int
	C1 *big.Int
}

type G1Point struct {
	X        *big.Int
	Y        *big.Int
	Infinity bool
}

type G2Point struct {
	X        Fp2
	Y        Fp2
	Infinity bool
}

func BaseFieldModulus() *big.Int { return clone(pModulus) }

func SubgroupOrder() *big.Int { return clone(rOrder) }

func Fp2NonResidue() *big.Int { return clone(nr2) }

func FpAdd(a, b *big.Int) *big.Int { return fpAdd(a, b) }

func FpSub(a, b *big.Int) *big.Int { return fpSub(a, b) }

func FpMul(a, b *big.Int) *big.Int { return fpMul(a, b) }

func FpInverse(a *big.Int) *big.Int { return fpInv(a) }

func NewFp2(c0, c1 *big.Int) Fp2 {
	return Fp2{C0: mod(c0), C1: mod(c1)}
}

func Fp2Add(a, b Fp2) Fp2 { return fp2Add(a, b) }

func Fp2Sub(a, b Fp2) Fp2 { return fp2Sub(a, b) }

func Fp2Mul(a, b Fp2) Fp2 { return fp2Mul(a, b) }

func Fp2Inverse(a Fp2) Fp2 { return fp2Inv(a) }

func Fp2Equal(a, b Fp2) bool { return fp2Equal(a, b) }

func G1Generator() G1Point {
	return G1Point{X: mustHex(g1GeneratorXHex), Y: mustHex(g1GeneratorYHex)}
}

func G2Generator() G2Point {
	return G2Point{
		X: NewFp2(mustHex(g2GeneratorX0Hex), mustHex(g2GeneratorX1Hex)),
		Y: NewFp2(mustHex(g2GeneratorY0Hex), mustHex(g2GeneratorY1Hex)),
	}
}

func G1OnCurve(p G1Point) bool {
	if p.Infinity {
		return true
	}
	return fpMul(p.Y, p.Y).Cmp(fpAdd(fpMul(fpMul(p.X, p.X), p.X), big.NewInt(4))) == 0
}

func G2OnCurve(p G2Point) bool {
	if p.Infinity {
		return true
	}
	left := fp2Mul(p.Y, p.Y)
	x3 := fp2Mul(fp2Mul(p.X, p.X), p.X)
	b := Fp2{C0: big.NewInt(4), C1: big.NewInt(4)}
	return fp2Equal(left, fp2Add(x3, b))
}

func G1Add(p, q G1Point) G1Point {
	if p.Infinity {
		return cloneG1(q)
	}
	if q.Infinity {
		return cloneG1(p)
	}

	var slope *big.Int
	if p.X.Cmp(q.X) == 0 {
		if fpAdd(p.Y, q.Y).Sign() == 0 || p.Y.Sign() == 0 {
			return G1Point{Infinity: true}
		}
		numerator := fpMul(big.NewInt(3), fpMul(p.X, p.X))
		denominator := fpMul(big.NewInt(2), p.Y)
		slope = fpMul(numerator, fpInv(denominator))
	} else {
		numerator := fpSub(q.Y, p.Y)
		denominator := fpSub(q.X, p.X)
		slope = fpMul(numerator, fpInv(denominator))
	}

	x := fpSub(fpSub(fpMul(slope, slope), p.X), q.X)
	y := fpSub(fpMul(slope, fpSub(p.X, x)), p.Y)
	return G1Point{X: x, Y: y}
}

func G2Add(p, q G2Point) G2Point {
	if p.Infinity {
		return cloneG2(q)
	}
	if q.Infinity {
		return cloneG2(p)
	}

	var slope Fp2
	if fp2Equal(p.X, q.X) {
		if fp2Sign(fp2Add(p.Y, q.Y)) == 0 || fp2Sign(p.Y) == 0 {
			return G2Point{Infinity: true}
		}
		numerator := fp2Mul(fp2FromUint64(3), fp2Mul(p.X, p.X))
		denominator := fp2Mul(fp2FromUint64(2), p.Y)
		slope = fp2Mul(numerator, fp2Inv(denominator))
	} else {
		numerator := fp2Sub(q.Y, p.Y)
		denominator := fp2Sub(q.X, p.X)
		slope = fp2Mul(numerator, fp2Inv(denominator))
	}

	x := fp2Sub(fp2Sub(fp2Mul(slope, slope), p.X), q.X)
	y := fp2Sub(fp2Mul(slope, fp2Sub(p.X, x)), p.Y)
	return G2Point{X: x, Y: y}
}

func G1ScalarMult(p G1Point, scalar *big.Int) G1Point {
	if scalar.Sign() < 0 {
		p = G1Neg(p)
		scalar = new(big.Int).Neg(scalar)
	}
	result := G1Point{Infinity: true}
	addend := cloneG1(p)
	for i := 0; i < scalar.BitLen(); i++ {
		if scalar.Bit(i) == 1 {
			result = G1Add(result, addend)
		}
		addend = G1Add(addend, addend)
	}
	return result
}

func G2ScalarMult(p G2Point, scalar *big.Int) G2Point {
	if scalar.Sign() < 0 {
		p = G2Neg(p)
		scalar = new(big.Int).Neg(scalar)
	}
	result := G2Point{Infinity: true}
	addend := cloneG2(p)
	for i := 0; i < scalar.BitLen(); i++ {
		if scalar.Bit(i) == 1 {
			result = G2Add(result, addend)
		}
		addend = G2Add(addend, addend)
	}
	return result
}

func G1Neg(p G1Point) G1Point {
	if p.Infinity {
		return G1Point{Infinity: true}
	}
	return G1Point{X: clone(p.X), Y: fpNeg(p.Y)}
}

func G2Neg(p G2Point) G2Point {
	if p.Infinity {
		return G2Point{Infinity: true}
	}
	return G2Point{X: cloneFp2(p.X), Y: fp2Neg(p.Y)}
}

func G1InSubgroup(p G1Point) bool {
	return G1ScalarMult(p, rOrder).Infinity
}

func G2InSubgroup(p G2Point) bool {
	return G2ScalarMult(p, rOrder).Infinity
}

func G1Equal(p, q G1Point) bool {
	if p.Infinity || q.Infinity {
		return p.Infinity == q.Infinity
	}
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

func G2Equal(p, q G2Point) bool {
	if p.Infinity || q.Infinity {
		return p.Infinity == q.Infinity
	}
	return fp2Equal(p.X, q.X) && fp2Equal(p.Y, q.Y)
}

func fp2FromUint64(n uint64) Fp2 {
	return Fp2{C0: new(big.Int).SetUint64(n), C1: new(big.Int)}
}

func fp2Add(a, b Fp2) Fp2 {
	return Fp2{C0: fpAdd(a.C0, b.C0), C1: fpAdd(a.C1, b.C1)}
}

func fp2Sub(a, b Fp2) Fp2 {
	return Fp2{C0: fpSub(a.C0, b.C0), C1: fpSub(a.C1, b.C1)}
}

func fp2Neg(a Fp2) Fp2 {
	return Fp2{C0: fpNeg(a.C0), C1: fpNeg(a.C1)}
}

func fp2Mul(a, b Fp2) Fp2 {
	ac := fpMul(a.C0, b.C0)
	bd := fpMul(a.C1, b.C1)
	ad := fpMul(a.C0, b.C1)
	dc := fpMul(a.C1, b.C0)
	return Fp2{C0: fpSub(ac, bd), C1: fpAdd(ad, dc)}
}

func fp2Inv(a Fp2) Fp2 {
	norm := fpAdd(fpMul(a.C0, a.C0), fpMul(a.C1, a.C1))
	invNorm := fpInv(norm)
	return Fp2{C0: fpMul(a.C0, invNorm), C1: fpNeg(fpMul(a.C1, invNorm))}
}

func fp2Equal(a, b Fp2) bool {
	return a.C0.Cmp(b.C0) == 0 && a.C1.Cmp(b.C1) == 0
}

func fp2Sign(a Fp2) int {
	if a.C0.Sign() != 0 {
		return a.C0.Sign()
	}
	return a.C1.Sign()
}

func fpAdd(a, b *big.Int) *big.Int { return mod(new(big.Int).Add(a, b)) }

func fpSub(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b)) }

func fpMul(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }

func fpNeg(a *big.Int) *big.Int { return mod(new(big.Int).Neg(a)) }

func fpInv(a *big.Int) *big.Int { return new(big.Int).ModInverse(a, pModulus) }

func mod(a *big.Int) *big.Int { return new(big.Int).Mod(a, pModulus) }

func clone(a *big.Int) *big.Int { return new(big.Int).Set(a) }

func cloneFp2(a Fp2) Fp2 { return Fp2{C0: clone(a.C0), C1: clone(a.C1)} }

func cloneG1(p G1Point) G1Point {
	if p.Infinity {
		return G1Point{Infinity: true}
	}
	return G1Point{X: clone(p.X), Y: clone(p.Y)}
}

func cloneG2(p G2Point) G2Point {
	if p.Infinity {
		return G2Point{Infinity: true}
	}
	return G2Point{X: cloneFp2(p.X), Y: cloneFp2(p.Y)}
}

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid reference parameter")
	}
	return n
}
