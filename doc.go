// Package selfsign provides functions for signing and verifying data,
// loading certificates and private keys, and downloading and caching public keys.
//
// This package is designed to facilitate cryptographic operations such as signing
// data with a private key, verifying signatures with a public key, loading
// certificates and private keys from PEM files, decrypting private keys, and
// downloading and caching public keys from a URI.
//
// Usage:
//
// To use this package, start by loading your private and public keys from PEM files:
//
//	privateKey, err := selfsign.LoadPrivateKey("path/to/private_key.pem", "password")
//	if err != nil {
//	    log.Fatalf("Failed to load private key: %v", err)
//	}
//
//	publicKey, err := selfsign.LoadCertificate("path/to/public_key.pem")
//	if err != nil {
//	    log.Fatalf("Failed to load public key: %v", err)
//	}
//
// Once you have loaded the keys, you can sign and verify data:
//
//	payload := []byte("This is a test payload")
//
//	signature, err := selfsign.SignData(privateKey, payload)
//	if err != nil {
//	    log.Fatalf("Failed to sign payload: %v", err)
//	}
//
//	fmt.Printf("Signature: %s\n", signature)
//
//	err = selfsign.VerifySignature(publicKey, payload, signature)
//	if err != nil {
//	    log.Fatalf("Failed to verify signature: %v", err)
//	}
//
//	fmt.Println("Signature verified successfully")
//
// Errors:
//
// This package defines several errors that may be returned during operation:
//
//	var (
//	    ErrInvalidPrivateKey = errors.New("invalid private key")
//	    ErrInvalidPublicKey  = errors.New("invalid public key")
//	    ErrSignFailed        = errors.New("signing payload failed")
//	    ErrVerifyFailed      = errors.New("verifying signature failed")
//	)
//
// These errors can be used to handle specific failure cases in your application.
package selfsign
