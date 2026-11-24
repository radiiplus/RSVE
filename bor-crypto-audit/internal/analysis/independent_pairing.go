package analysis

import (
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

type AffinePair struct {
	G1 []byte
	G2 []byte
}

func blstPairingCheck(pairs []AffinePair) (bool, error) {
	if len(pairs) == 0 {
		return true, nil
	}
	ctx := blst.PairingCtx(false, nil)
	added := 0
	for i, pair := range pairs {
		if allZeroBytes(pair.G1) || allZeroBytes(pair.G2) {
			continue
		}
		p, err := parseBlstG1(pair.G1)
		if err != nil {
			return false, fmt.Errorf("pair %d G1: %w", i, err)
		}
		q, err := parseBlstG2(pair.G2)
		if err != nil {
			return false, fmt.Errorf("pair %d G2: %w", i, err)
		}
		if !p.InG1() {
			return false, fmt.Errorf("pair %d G1 is outside subgroup", i)
		}
		if !q.InG2() {
			return false, fmt.Errorf("pair %d G2 is outside subgroup", i)
		}
		blst.PairingRawAggregate(ctx, q, p)
		added++
	}
	if added == 0 {
		return true, nil
	}
	blst.PairingCommit(ctx)
	return blst.PairingFinalVerify(ctx), nil
}

func parseBlstG1(encoded []byte) (*blst.P1Affine, error) {
	if len(encoded) != 128 {
		return nil, fmt.Errorf("invalid EIP-2537 G1 encoding length %d", len(encoded))
	}
	if allZeroBytes(encoded) {
		infinity := make([]byte, 48)
		infinity[0] = 0xc0
		p := new(blst.P1Affine).Uncompress(infinity)
		if p == nil {
			return nil, fmt.Errorf("blst rejected G1 infinity")
		}
		return p, nil
	}
	serialized := make([]byte, 96)
	copy(serialized[:48], encoded[16:64])
	copy(serialized[48:], encoded[80:128])
	p := new(blst.P1Affine).Deserialize(serialized)
	if p == nil {
		return nil, fmt.Errorf("blst rejected G1 coordinates")
	}
	return p, nil
}

func parseBlstG2(encoded []byte) (*blst.P2Affine, error) {
	if len(encoded) != 256 {
		return nil, fmt.Errorf("invalid EIP-2537 G2 encoding length %d", len(encoded))
	}
	if allZeroBytes(encoded) {
		infinity := make([]byte, 96)
		infinity[0] = 0xc0
		q := new(blst.P2Affine).Uncompress(infinity)
		if q == nil {
			return nil, fmt.Errorf("blst rejected G2 infinity")
		}
		return q, nil
	}
	serialized := make([]byte, 192)
	copy(serialized[0:48], encoded[80:128])
	copy(serialized[48:96], encoded[16:64])
	copy(serialized[96:144], encoded[208:256])
	copy(serialized[144:192], encoded[144:192])
	q := new(blst.P2Affine).Deserialize(serialized)
	if q == nil {
		return nil, fmt.Errorf("blst rejected G2 coordinates")
	}
	return q, nil
}

func allZeroBytes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
