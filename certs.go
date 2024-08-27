/*
 * Copyright (c) 2024 Intergreatme. All rights reserved.
 */

package certcrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// ReadPKCS12 reads a .pfx file and extracts them RSA private key and certificate
func ReadPKCS12(filepath string, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// Read the .pfx file
	pfxData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read .pfx file: %v", err)
	}

	// Decode the PKCS#12 file
	privateKey, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode .pfx file: %v", err)
	}

	// Type assert the private key to an *rsa.PrivateKey
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not of type *rsa.PrivateKey")
	}

	return rsaPrivateKey, cert, nil
}

// WriteCertificateToPEM writes an x509 certificate to a PEM-encoded file
func WriteCertificateToPEM(cert *x509.Certificate, filepath string) error {
	// Create a PEM block with the certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Write the PEM block to the specified file
	err := os.WriteFile(filepath, certPEM, 0644)
	if err != nil {
		return fmt.Errorf("unable to write certificate to file: %v", err)
	}

	return nil
}

// ReadCertFromPEM reads an x509 certificate from a PEM-encoded file
func ReadCertFromPEM(filepath string) (*x509.Certificate, error) {
	// Read the PEM file
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("unable to read PEM file: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the x509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// DownloadCert downloads a certificate from a given URI and writes it to a PEM file
func DownloadCert(uri string, filepath string) error {
	// Perform HTTP GET request
	resp, err := http.Get(uri)
	if err != nil {
		return fmt.Errorf("unable to perform GET request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	var pemData []byte

	// Check if the response is JSON-encoded
	if resp.Header.Get("Content-Type") == "application/json" {
		var result map[string]string
		err := json.Unmarshal(body, &result)
		if err != nil {
			return fmt.Errorf("unable to unmarshal JSON response: %v", err)
		}
		pemData = []byte(result["public_key"])
	} else {
		pemData = body
	}

	// Write the PEM data to a file
	err = os.WriteFile(filepath, pemData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write PEM file: %v", err)
	}

	return nil
}
