package selfsign

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
)

// decryptPrivateKey decrypts the encrypted private key using AES-GCM with the provided password.
func decryptPrivateKey(encryptedKey []byte, password string) ([]byte, error) {
	// Derive a key from the password using SHA-256.
	hash := sha256.Sum256([]byte(password))

	// Create a new AES cipher block from the derived key.
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}

	// Create a new GCM (Galois/Counter Mode) AEAD (Authenticated Encryption with Associated Data) cipher.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the size of the nonce used by the GCM.
	nonceSize := gcm.NonceSize()
	if len(encryptedKey) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Split the encrypted key into the nonce and the actual ciphertext.
	nonce, ciphertext := encryptedKey[:nonceSize], encryptedKey[nonceSize:]

	// Decrypt the ciphertext using the nonce and the GCM cipher.
	decryptedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Return the decrypted private key.
	return decryptedKey, nil
}
