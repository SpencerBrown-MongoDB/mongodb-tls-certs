package mx509

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/SpencerBrown/mongodb-tls-certs/config"
	"math/big"
	"net"
	"time"
)

// CreateCert creates a certificate from a private key and a CA or self-signed
// a flag controls what kind of certificate is generated
// returns the certificate, and a byte slice PEM-formatted version
func CreateCert(configCert *config.Cert, key crypto.PrivateKey, CAkey crypto.PrivateKey, CACert *x509.Certificate) (*x509.Certificate, []byte, error) {
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
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{configCert.Subject.O},
			OrganizationalUnit: []string{configCert.Subject.OU},
			CommonName:         configCert.Subject.CN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	var derBytes []byte
	switch configCert.Type {
	case config.ServerCert: // Can authenticate as client or server, has SAN with DNS names
		var DNSNames = make([]string, 0)
		var IPAddresses = make([]net.IP, 0)
		for _, h := range configCert.Hosts {
			if ip := net.ParseIP(h); ip != nil {
				IPAddresses = append(IPAddresses, ip)
			} else {
				DNSNames = append(DNSNames, h)
			}
		}
		template.DNSNames = DNSNames
		template.IPAddresses = IPAddresses
		template.KeyUsage = keyUsage
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	case config.ClientCert: // Can authenticate as client
		template.KeyUsage = keyUsage
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	case config.RootCACert: // Can sign certificates, is a CA
		template.IsCA = true
		keyUsage |= x509.KeyUsageCertSign
		template.KeyUsage = keyUsage
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey(key), key)
	case config.IntermediateCACert: // Can sign certificates, is a CA
		template.IsCA = true
		keyUsage |= x509.KeyUsageCertSign
		keyUsage |= x509.KeyUsageCRLSign
		template.KeyUsage = keyUsage
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	case config.OCSPSigningCert: // Can sign OCSP responses
		template.KeyUsage = keyUsage
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse der bytes: %v", err)
	}
	certBlk := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   derBytes,
	}

	return cert, pem.EncodeToMemory(&certBlk), nil
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

// publicKey gets the public key from a private key
func publicKey(key crypto.PrivateKey) crypto.PublicKey {
	return &key.(*rsa.PrivateKey).PublicKey
}
