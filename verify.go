/*
 * Copyright (c) 2024 Intergreatme. All rights reserved.
 */

package certcrypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
)

// VerifySignature verifies the signature of the input data using the provided public key.
func VerifySignature(publicKey *rsa.PublicKey, data []byte, signature []byte) error {
	// Compute the SHA-512 hash of the input data.
	hashed := sha512.Sum512(data)

	// Verify the signature using the public key with PKCS1v15.
	// The crypto.SHA512 argument specifies the hashing algorithm used.
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashed[:], signature)
}
