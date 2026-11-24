package analysis

import (
	"math/big"

	"bor-crypto-audit/internal/reference"
)

// ScalarPair represents points P=[G1Scalar]G1 and Q=[G2Scalar]G2.
// Scalars may be negative or outside [0,r); they are interpreted modulo r.
type ScalarPair struct {
	G1Scalar *big.Int
	G2Scalar *big.Int
}

// PairingProductExponent returns sum(a_i*b_i) mod r. By bilinearity, this is
// the exponent of the product relative to e(G1,G2); the product is identity
// exactly when the returned exponent is zero. It uses only math/big scalar
// arithmetic and the independently pinned subgroup order.
func PairingProductExponent(pairs []ScalarPair) *big.Int {
	r := reference.SubgroupOrder()
	exponent := new(big.Int)
	for _, pair := range pairs {
		a := scalarMod(pair.G1Scalar, r)
		b := scalarMod(pair.G2Scalar, r)
		term := new(big.Int).Mul(a, b)
		exponent.Add(exponent, term)
		exponent.Mod(exponent, r)
	}
	return exponent
}

// PairingProductIsIdentity reports the mathematical identity condition for
// tuples generated as scalar multiples of the standard subgroup generators.
func PairingProductIsIdentity(pairs []ScalarPair) bool {
	return PairingProductExponent(pairs).Sign() == 0
}

func scalarMod(scalar, modulus *big.Int) *big.Int {
	if scalar == nil {
		return new(big.Int)
	}
	return new(big.Int).Mod(new(big.Int).Set(scalar), modulus)
}
