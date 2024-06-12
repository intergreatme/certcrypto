package selfsign

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"
)

// LoadPFXCertificate loads a certificate from a PFX file encrypted with password.
func LoadPFXCertificate(path, password string) (*x509.Certificate, error) {
	// Read the PFX file containing the certificate.
	pfxData, err := os.ReadFile(path)
	if err != nil {
		return nil, err // Return an error if the file cannot be read.
	}

	// Decode the PFX data to extract the certificate.
	privateKey, certificate, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return nil, err // Return an error if the PFX data cannot be decoded.
	}

	// Assert the private key type and discard it if present.
	if _, ok := privateKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("unexpected private key type in PFX file")
	}

	// Return the parsed x509 certificate.
	return certificate, nil
}

// LoadPFXCertificate loads a PFX certificate without requiring a password.
// Specific use for IGM's Certificate that's returned.
func LoadPFXCertificateExclPass(path string) (*x509.Certificate, error) {
	// Read the PFX file containing the certificate.
	pfxData, err := os.ReadFile(path)
	if err != nil {
		return nil, err // Return an error if the file cannot be read.
	}

	// Decode the PFX data to extract the certificate.
	privateKey, certificate, err := pkcs12.Decode(pfxData, "")
	if err != nil {
		return nil, err // Return an error if the PFX data cannot be decoded.
	}

	// Assert the private key type and discard it if present.
	if _, ok := privateKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("unexpected private key type in PFX file")
	}

	// Return the parsed x509 certificate.
	return certificate, nil
}

// LoadPEMCertificate loads a PEM encoded certificate from the specified path.
func LoadPEMCertificate(path string) (*x509.Certificate, error) {
	// Read the PEM file.
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err // Return an error if the file cannot be read.
	}

	// Decode the PEM data to extract the certificate.
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	// Parse the X.509 certificate.
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err // Return an error if the certificate cannot be parsed.
	}

	return certificate, nil
}

// LoadPrivateKey loads an encrypted private key from a PEM file.
func LoadPrivateKey(path, password string) (*rsa.PrivateKey, error) {
	fmt.Println("Loading private key from:", path)

	// Read the PEM file containing the encrypted private key.
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %v", err)
	}

	// Decode the PEM data to extract the PEM block.
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	fmt.Println("PEM block type:", block.Type)

	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}

	// Decrypt the private key using the provided password.
	privBytes, err := decryptPrivateKey(block.Bytes, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	// Try to parse the decrypted private key as PKCS1.
	privKey, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err == nil {
		fmt.Println("Successfully parsed PKCS1 private key")
		return privKey, nil
	}

	// If parsing as PKCS1 fails, try to parse it as PKCS8.
	privKeyInterface, err := x509.ParsePKCS8PrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %v", err)
	}

	// Assert the parsed key is of type *rsa.PrivateKey.
	privKey, ok := privKeyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to cast private key to *rsa.PrivateKey")
	}

	// Return the parsed RSA private key.
	fmt.Println("Successfully loaded and parsed private key")
	return privKey, nil
}

// Download downloads the certificate from the specified URI and stores it at the specified path.
func Download(uri string, saveDir string, fileName string) error {
	// Download the certificate from the URI.
	resp, err := http.Get(uri)
	if err != nil {
		return fmt.Errorf("failed to download certificate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download certificate: received status code %d", resp.StatusCode)
	}

	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read certificate response: %v", err)
	}

	// Check if the response body is base64 encoded.
	decodedBody, err := base64.StdEncoding.DecodeString(string(body))
	if err == nil {
		// Successfully decoded base64, so use the decoded data.
		body = decodedBody
	}

	// Ensure the save directory exists.
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Construct the full file path.
	savePath := filepath.Join(saveDir, fileName)
	fmt.Printf("Saving certificate to: %s\n", savePath) // Debug statement

	// Write the certificate to the save path.
	if err := os.WriteFile(savePath, body, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	return nil
}

// DownloadAndExtractCert downloads the certificate from the specified URI,
// extracts the public key from the JSON response, and saves it as a PEM file.
func DownloadAndExtractCert(uri, saveDir, fileName string) error {
	// Download the certificate from the URI.
	resp, err := http.Get(uri)
	if err != nil {
		return fmt.Errorf("failed to download certificate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download certificate: received status code %d", resp.StatusCode)
	}

	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read certificate response: %v", err)
	}

	// Unmarshal the JSON response to extract the certificate.
	var certResponse struct {
		PublicKey string `json:"public_key"`
	}
	err = json.Unmarshal(body, &certResponse)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// Ensure the save directory exists.
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Construct the full file path.
	savePath := filepath.Join(saveDir, fileName)
	fmt.Printf("Saving certificate to: %s\n", savePath) // Debug statement

	// Write the public key to the save path.
	if err := os.WriteFile(savePath, []byte(certResponse.PublicKey), 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	return nil
}
