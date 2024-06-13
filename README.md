# CertCrypto Package

This Go package provides functionalities to manage certificates and keys, sign and verify data using RSA keys and x509 certificates. The package supports reading and saving certificates from PEM and PKCS#12 files, signing data with a private key, and verifying signatures with a public key.

## Features

- Load RSA private keys and certificates from PKCS#12 (.pfx) files.
- Load certificates from PEM files.
- Sign data using RSA private keys.
- Verify data signatures using RSA public keys extracted from x509 certificates.
- Download and store certificates from a URI in PEM format.

## Installation

To install the package, use `go get`:

```sh
go get github.com/intergreatme/certcrypto
```

## Usage

### Reading Keys and Certificates

#### Read a Certificate and Private Key from a PKCS#12 File

To load a certificate and private key from a PKCS#12 (.pfx) file:

```go
certificate, privateKey, err := certcrypto.ReadPKCS12("path/to/certificate.pfx", "password")
if err != nil {
    log.Fatalf("Failed to load certificate and private key: %v", err)
}
```

#### Read a Certificate from a PEM File

To load a certificate from a PEM file:

```go
certificate, err := certcrypto.ReadCertFromPEM("path/to/cert.pem")
if err != nil {
    log.Fatalf("Failed to load certificate: %v", err)
}
```

#### Save a Certificate to a PEM File

To save a certificate to a PEM file:

```go
err := certcrypto.WriteCertificateToPEM(certificate, "path/to/output/cert.pem")
if err != nil {
    log.Fatalf("Failed to write certificate to PEM file: %v", err)
}
```

### Signing Data

To sign data using a private key:

```go
data := []byte("data to be signed")
signature, err := certcrypto.SignData(privateKey, data)
if err != nil {
    log.Fatalf("Failed to sign data: %v", err)
}
```

### Verifying Data

To verify the signature of data using a public key extracted from a certificate:

```go
err := certcrypto.VerifySignature(certificate.PublicKey.(*rsa.PublicKey), data, signature)
if err != nil {
    log.Fatalf("Failed to verify signature: %v", err)
}
fmt.Println("Signature verified successfully!")
```

### Downloading and Storing Certificates

To download and save a certificate that contains both the certificate and the public key in .pem format:

```go
uri := "https://example.com/path/to/public/key"
filepath := "path/to/save/cert.pem"
err := certcrypto.DownloadCert(uri, filepath)
if err != nil {
    log.Fatalf("Failed to download and save public key: %v", err)
}

```

### Complete Example

To download and save a certificate, which includes the public key, in .pem format:

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "log"

    "github.com/intergreatme/certcrypto"
)

func main() {
    // Path to your certificate and private key files
    pfxPath := "path/to/certificate.pfx"
    password := "YourPassword"

    // Load your certificate and private key
    cert, privateKey, err := certcrypto.ReadPKCS12(pfxPath, password)
    if err != nil {
        log.Fatalf("Failed to load certificate and private key: %v", err)
    }

    // Data to be signed
    data := []byte("hello, world")

    // Sign the data
    signature, err := certcrypto.SignData(privateKey, data)
    if err != nil {
        log.Fatalf("Failed to sign data: %v", err)
    }

    // Verify the signed data using your own public key
    err = certcrypto.VerifySignature(cert.PublicKey.(*rsa.PublicKey), data, signature)
    if err != nil {
        log.Fatalf("Failed to verify data: %v", err)
    }

    // Output success message
    fmt.Println("Data signed and verified successfully!")
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.