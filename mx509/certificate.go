package mx509

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type CertParameters struct {
	O       string
	OU      string
	CN      string
	Servers []string
}

// GetPrivateKey gets the private kay from a PEM-format byte slice
func GetPrivateKey(pemKey []byte) (crypto.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemKey)
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM private key")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key type not recognized")
	}
	return rsaKey, nil
}

// GetCertificate gets the certificate from a PEM-format byte slice
func GetCertificate(pemCert []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemCert)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing X.509 certificate: %v", err)
	}
	return cert, nil
}

// CreateRootCA creates a root CA certificate from a private key
// returned as a byte slice PEM-formatted
func CreateRootCA(key crypto.PrivateKey, parms *CertParameters) ([]byte, error) {

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	keyUsage |= x509.KeyUsageKeyEncipherment
	// Allow certificate signing
	keyUsage |= x509.KeyUsageCertSign

	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.AddDate(10, 0, 0) // good for 10 years

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{parms.O},
			OrganizationalUnit: []string{parms.OU},
			CommonName:         parms.CN,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(key), key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	certBlk := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   derBytes,
	}
	return pem.EncodeToMemory(&certBlk), nil
}

// CreateServerCert creates a server certificate from a private key and a CA
// returned as a byte slice PEM-formatted
func CreateServerCert(key crypto.PrivateKey, parms *CertParameters, CAkey crypto.PrivateKey, CACert *x509.Certificate) ([]byte, error) {

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	keyUsage |= x509.KeyUsageKeyEncipherment

	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.AddDate(0, 0, 90) // good for 90 days

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{parms.O},
			OrganizationalUnit: []string{parms.OU},
			CommonName:         parms.CN,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		DNSNames: parms.Servers,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	certBlk := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   derBytes,
	}
	return pem.EncodeToMemory(&certBlk), nil
}

func publicKey(key crypto.PrivateKey) crypto.PublicKey {
	return &key.(*rsa.PrivateKey).PublicKey
}
