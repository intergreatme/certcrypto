package certcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
)

// SignData signs the input data using the provided private key.
func SignData(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	// Compute the SHA-512 hash of the input data.
	hashed := sha512.Sum512(data)

	// Sign the hashed data using the private key with PKCS1v15.
	// The crypto.SHA512 argument specifies the hashing algorithm used.
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashed[:])
}
