package selfsign

import "errors"

var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrSignFailed        = errors.New("signing payload failed")
	ErrVerifyFailed      = errors.New("verifying signature failed")
)
