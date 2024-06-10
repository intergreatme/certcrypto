package selfsign

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
)

// DownloadAndCachePublicKey downloads the public key from the specified URI and caches it at the specified path.
func DownloadAndCachePublicKey(uri, cachePath string) (*x509.Certificate, error) {
	// Check if the public key is already cached.
	if _, err := os.Stat(cachePath); err == nil {
		// Load the cached public key.
		return LoadCertificate(cachePath)
	}

	// Download the public key from the URI.
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to download public key: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key response: %v", err)
	}

	// Decode the base64 encoded public key.
	decodedKey, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	// Write the decoded key to the cache path.
	if err := os.WriteFile(cachePath, decodedKey, 0644); err != nil {
		return nil, fmt.Errorf("failed to cache public key: %v", err)
	}

	// Load the cached public key.
	return LoadCertificate(cachePath)
}
