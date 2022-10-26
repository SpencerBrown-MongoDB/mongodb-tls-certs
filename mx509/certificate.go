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
	"net"
	"time"
)

// Certificate types handled by this package
const (
	_ = iota // don't allow zero as a valid certificate type
	RootCACert
	IntermediateCACert
	OCSPSigningCert
	ServerCert
	ClientCert
)

type CertInfo struct {
	CertType  int // certificate type
	ValidDays int // how many days it should remain valid
	O         string
	OU        string
	CN        string
	Hosts     []string
}

// CreateCSR creates a private key and certificate signing request, currently only for a client certificate.
// the CertInfo needs only the CertType to be Client, and the O/OU/CN filled in for the Subject Name.
func CreateCSR(certInfo *CertInfo, key crypto.PrivateKey) ([]byte, error) {
	switch certInfo.CertType {
	case ClientCert:
		var org, orgUnit []string
		if certInfo.O != "" {
			org = []string{certInfo.O}
		}
		if certInfo.OU != "" {
			orgUnit = []string{certInfo.OU}
		}
		template := x509.CertificateRequest{
			Subject: pkix.Name{
				Organization:       org,
				OrganizationalUnit: orgUnit,
				CommonName:         certInfo.CN,
			},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
		if err != nil {
			return nil, fmt.Errorf("error creating CSR: %v", err)
		}
		csrPEM := pem.Block{
			Type:    "CERTIFICATE REQUEST",
			Headers: nil,
			Bytes:   csrDER,
		}
		return pem.EncodeToMemory(&csrPEM), nil
	default:
		return nil, fmt.Errorf("unsupported certificate type (only client CSRs currently supported)")
	}
}

// CreateCert creates a certificate from a private key and a CA, or a self-signed certificate
// a flag controls what kind of certificate is generated
// returns the certificate, and a byte slice PEM-formatted version
func CreateCert(certInfo *CertInfo, key crypto.PrivateKey, CAkey crypto.PrivateKey, CACert *x509.Certificate) (*x509.Certificate, []byte, error) {
	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In the context of TLS this KeyUsage is particular to RSA key exchange and authentication.
	keyUsage |= x509.KeyUsageKeyEncipherment

	var notBefore time.Time = time.Now()
	notAfter := notBefore.AddDate(0, 0, certInfo.ValidDays) // good for this many days
	var org, orgUnit []string
	if certInfo.O != "" {
		org = []string{certInfo.O}
	}
	if certInfo.OU != "" {
		orgUnit = []string{certInfo.OU}
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       org,
			OrganizationalUnit: orgUnit,
			CommonName:         certInfo.CN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	var derBytes []byte
	switch certInfo.CertType {
	case ServerCert: // Can authenticate as client or server, has SAN with DNS names and IP addresses
		var DNSNames = make([]string, 0)
		var IPAddresses = make([]net.IP, 0)
		for _, h := range certInfo.Hosts {
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
	case ClientCert: // Can authenticate as client
		template.KeyUsage = keyUsage
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	case RootCACert: // Can sign certificates, is a CA, is self-signed
		template.IsCA = true
		keyUsage |= x509.KeyUsageCertSign
		template.KeyUsage = keyUsage
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey(key), key)
	case IntermediateCACert: // Can sign certificates, is a CA signed by another CA
		template.IsCA = true
		keyUsage |= x509.KeyUsageCertSign
		keyUsage |= x509.KeyUsageCRLSign
		template.KeyUsage = keyUsage
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	case OCSPSigningCert: // Can sign OCSP responses
		template.KeyUsage = keyUsage
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, CACert, publicKey(key), CAkey)
	default:
		return nil, nil, fmt.Errorf("error: invalid certificate type %d", certInfo.CertType)
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

// GetCSR gets the certificate from a PEM-format byte slice
func GetCSR(pemCSR []byte) (*x509.CertificateRequest, error) {
	pemBlock, _ := pem.Decode(pemCSR)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing X.509 CSR: %v", err)
	}
	return csr, nil
}

// publicKey gets the public key from a private key
func publicKey(key crypto.PrivateKey) crypto.PublicKey {
	return &key.(*rsa.PrivateKey).PublicKey
}
