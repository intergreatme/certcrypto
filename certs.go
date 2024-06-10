package selfsign

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadCertificate loads a certificate from a PEM file.
func LoadCertificate(path string) (*x509.Certificate, error) {
	// Read the PEM file containing the certificate.
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err // Return an error if the file cannot be read.
	}

	// Decode the PEM data to extract the PEM block.
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate") // Return an error if the PEM block is invalid or not a certificate.
	}

	// Parse the certificate from the PEM block.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err // Return an error if the certificate cannot be parsed.
	}

	// Return the parsed x509 certificate.
	return cert, nil
}

// LoadPrivateKey loads an encrypted private key from a PEM file.
func LoadPrivateKey(path, password string) (*rsa.PrivateKey, error) {
	// Read the PEM file containing the encrypted private key.
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode the PEM data to extract the PEM block.
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	// Decrypt the private key using the provided password.
	privBytes, err := decryptPrivateKey(block.Bytes, password)
	if err != nil {
		return nil, err
	}

	// Try to parse the decrypted private key as PKCS1.
	privKey, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err == nil {
		return privKey, nil
	}

	// If parsing as PKCS1 fails, try to parse it as PKCS8.
	privKeyInterface, err := x509.ParsePKCS8PrivateKey(privBytes)
	if err != nil {
		return nil, err
	}

	// Assert the parsed key is of type *rsa.PrivateKey.
	privKey, ok := privKeyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to cast private key to *rsa.PrivateKey")
	}

	// Return the parsed RSA private key.
	return privKey, nil
}
