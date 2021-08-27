package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/SpencerBrown/mongodb-x509/mx509"
	"log"
	"os"
)

const rootCAFileName = "root-ca"
const serverFileName = "server"

func main() {

	// Create Root CA key and certificate
	rootCAKey, err := createPrivateKey(rootCAFileName)
	if err != nil {
		log.Fatalf("Error creating %s private key: %v", rootCAFileName, err)
	}
	parms := mx509.CertParameters{
		O:  "MongoDB",
		OU: "Root CA",
		CN: "Repro",
	}
	err = createRootCA(rootCAFileName, &parms, rootCAKey)
	if err != nil {
		log.Fatalf("Error creating %s certificate: %v", rootCAFileName, err)
	}

	// create Server private key and certificate
	serverKey, err := createPrivateKey(serverFileName)
	if err != nil {
		log.Fatalf("Error creating %s private key: %v", serverFileName, err)
	}

	hosts := []string{"mongodb-local.computer"}
	parms = mx509.CertParameters{
		O:       "MongoDB",
		OU:      "Server",
		CN:      "Repro",
		Servers: hosts,
	}

	// get the root CA key and certificate
	rootCAKey, err = getPrivateKey("root-ca", "key")
	if err != nil {
		log.Fatalf("Error reading root CA key: %v", err)
	}
	rootCAcert, err := getCertificate("root-ca", "pem")
	if err != nil {
		log.Fatalf("Error reading root CA certificate: %v", err)
	}

	// create the server certificate
	err = createServerCert("server", &parms, serverKey, rootCAKey, rootCAcert)
}

// createPrivateKey creates private key and writes it to the file "<prefix>.key" in PEM format
func createPrivateKey(prefix string) (crypto.PrivateKey, error) {
	key, PEMkey, err := mx509.CreatePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("error creating private key %v", err)
	}
	err = writeFile(prefix, "key", PEMkey, true)
	if err != nil {
		return nil, fmt.Errorf("error writing private key file: %v", err)
	}
	return key, nil
}

// createRootCA creates a root CA certificate for a private key,
// and writes it to the file <prefix>.pem
func createRootCA(prefix string, parms *mx509.CertParameters, key crypto.PrivateKey) error {
	PEMcert, err := mx509.CreateRootCA(key, parms)
	if err != nil {
		return fmt.Errorf("error creating root CA certificate %v", err)
	}
	err = writeFile(prefix, "pem", PEMcert, false)
	if err != nil {
		return fmt.Errorf("error writing root CA file: %v", err)
	}
	return nil
}

// createServerCert creates a server certificate for a private key and CA,
// and writes it to the file <prefix>.pem
func createServerCert(prefix string, parms *mx509.CertParameters, key crypto.PrivateKey, CAKey crypto.PrivateKey, CACert *x509.Certificate) error {
	PEMcert, err := mx509.CreateServerCert(key, parms, CAKey, CACert)
	if err != nil {
		return fmt.Errorf("error creating server certificate %v", err)
	}
	err = writeFile(prefix, "pem", PEMcert, false)
	if err != nil {
		return fmt.Errorf("error writing server certificate file: %v", err)
	}
	return nil
}

// getPrivateKey reads a private key from the file <prefix>.<extension>
func getPrivateKey(prefix string, extension string) (crypto.PrivateKey, error) {
	content, err := readFile(prefix, extension)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}
	key, err := mx509.GetPrivateKey(content)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key file: %v", err)
	}
	return key, nil
}

// getCertificate reads a certificate from the file <prefix>.<extension>
func getCertificate(prefix string, extension string) (*x509.Certificate, error) {
	content, err := readFile(prefix, extension)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate file: %v", err)
	}
	cert, err := mx509.GetCertificate(content)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate file: %v", err)
	}
	return cert, nil
}

// writeFile writes file <prefix>.<extension> with content, and marks it world-readable or user-readable
func writeFile(prefix string, extension string, content []byte, private bool) error {
	fn := prefix + "." + extension
	perms := os.FileMode(0644)
	if private {
		perms = os.FileMode(0600)
	}
	err := os.WriteFile(fn, content, perms)
	if err != nil {
		return fmt.Errorf("error writing file %s: %v", fn, err)
	}
	log.Printf("'%s' file created", fn)
	return nil
}

// readFile reads <prefix>.<extension> and returns slice of bytes
func readFile(prefix string, extension string) ([]byte, error) {
	fn := prefix + "." + extension
	content, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", fn, err)
	}
	return content, nil
}
