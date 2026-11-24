package boradapter

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type PointInspection struct {
	DecoderAccepted       bool   `json:"decoder_accepted"`
	DecoderError          string `json:"decoder_error,omitempty"`
	GnarkCoordinatesValid bool   `json:"gnark_coordinates_valid"`
	GnarkFieldError       string `json:"gnark_field_error,omitempty"`
	GnarkIsOnCurve        *bool  `json:"gnark_is_on_curve,omitempty"`
	GnarkIsInSubGroup     *bool  `json:"gnark_is_in_subgroup,omitempty"`
}

func InspectG1(input []byte) PointInspection {
	_, decoderErr := decodePointG1(input)
	result := PointInspection{DecoderAccepted: decoderErr == nil}
	if decoderErr != nil {
		result.DecoderError = decoderErr.Error()
	}
	if len(input) != 128 {
		result.GnarkFieldError = "invalid g1 point length"
		return result
	}
	x, err := decodeBLS12381FieldElement(input[:64])
	if err != nil {
		result.GnarkFieldError = err.Error()
		return result
	}
	y, err := decodeBLS12381FieldElement(input[64:])
	if err != nil {
		result.GnarkFieldError = err.Error()
		return result
	}
	point := bls12381.G1Affine{X: x, Y: y}
	result.GnarkCoordinatesValid = true
	result.GnarkIsOnCurve = boolPointer(point.IsOnCurve())
	result.GnarkIsInSubGroup = boolPointer(point.IsInSubGroup())
	return result
}

func InspectG2(input []byte) PointInspection {
	_, decoderErr := decodePointG2(input)
	result := PointInspection{DecoderAccepted: decoderErr == nil}
	if decoderErr != nil {
		result.DecoderError = decoderErr.Error()
	}
	if len(input) != 256 {
		result.GnarkFieldError = "invalid g2 point length"
		return result
	}
	x0, err := decodeBLS12381FieldElement(input[:64])
	if err != nil {
		result.GnarkFieldError = err.Error()
		return result
	}
	x1, err := decodeBLS12381FieldElement(input[64:128])
	if err != nil {
		result.GnarkFieldError = err.Error()
		return result
	}
	y0, err := decodeBLS12381FieldElement(input[128:192])
	if err != nil {
		result.GnarkFieldError = err.Error()
		return result
	}
	y1, err := decodeBLS12381FieldElement(input[192:])
	if err != nil {
		result.GnarkFieldError = err.Error()
		return result
	}
	point := bls12381.G2Affine{X: bls12381.E2{A0: x0, A1: x1}, Y: bls12381.E2{A0: y0, A1: y1}}
	result.GnarkCoordinatesValid = true
	result.GnarkIsOnCurve = boolPointer(point.IsOnCurve())
	result.GnarkIsInSubGroup = boolPointer(point.IsInSubGroup())
	return result
}

func boolPointer(value bool) *bool { return &value }
