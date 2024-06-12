```markdown
# Sign/Verify Package

This Go package provides functionalities to sign and verify data using RSA keys and x509 certificates. The package supports loading encrypted private keys and certificates from PEM files, signing data with a private key, and verifying signatures with a public key.

## Features

- Load encrypted private keys from PEM files.
- Load certificates from PEM files.
- Sign data using RSA private keys.
- Verify data signatures using RSA public keys extracted from x509 certificates.
- Download and storing of of certificates from a URI.

## Installation

To install the package, use `go get`:

```sh
go get github.com/intergreatme/selfsign
```

## Usage

### Loading Keys and Certificates

#### Load a Private Key

To load an encrypted private key from a PEM file:

```go
privateKey, err := selfsign.LoadPrivateKey("path/to/private_key.pem", "password")
if err != nil {
    log.Fatalf("Failed to load private key: %v", err)
}
```

#### Load a Certificate

To load a certificate from a PEM file:

```go
certificate, err := selfsign.LoadPEMCertificate("path/to/cert.pem")
if err != nil {
    log.Fatalf("Failed to load certificate: %v", err)
}
```

### Signing Data

To sign data using a private key:

```go
data := []byte("data to be signed")
signature, err := selfsign.SignData(privateKey, data)
if err != nil {
    log.Fatalf("Failed to sign data: %v", err)
}
```

### Verifying Data

To verify the signature of data using a public key extracted from a certificate:

```go
err := selfsign.VerifySignature(certificate.PublicKey.(*rsa.PublicKey), data, signature)
if err != nil {
    log.Fatalf("Failed to verify signature: %v", err)
}
fmt.Println("Signature verified successfully!")
```

### Downloading and storing of Certificates

To download and save a public key from a URI:

```go
uri := "https://example.com/path/to/public/key"
saveDir := "path/to/save"
fileName := "cert.pem"
err := selfsign.DownloadAndExtractCertificate(uri, saveDir, fileName)
if err != nil {
    log.Fatalf("Failed to download and save public key: %v", err)
}
```

### Complete Example

Here's an example demonstrating how to use the package to sign and verify data:

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "log"

    "github.com/intergreatme/selfsign"
)

func main() {
    // Paths to your certificate and private key files
    myCertPath := "my_cert.pem"
    myKeyPath := "my_key.pem"
    myPassword := "YourPassword"

    // Load your certificate
    myCert, err := selfsign.LoadPEMCertificate(myCertPath)
    if err != nil {
        log.Fatalf("Failed to load certificate: %v", err)
    }

    // Load your private key
    myPrivateKey, err := selfsign.LoadPrivateKey(myKeyPath, myPassword)
    if err != nil {
        log.Fatalf("Failed to load private key: %v", err)
    }

    // Data to be signed
    data := []byte("hello, world")

    // Sign the data
    signature, err := selfsign.SignData(myPrivateKey, data)
    if err != nil {
        log.Fatalf("Failed to sign data: %v", err)
    }

    // Verify the signed data using your own public key
    err = selfsign.VerifySignature(myCert.PublicKey.(*rsa.PublicKey), data, signature)
    if err != nil {
        log.Fatalf("Failed to verify data: %v", err)
    }

    // Output success message
    fmt.Println("Data signed and verified successfully!")
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.