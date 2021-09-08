package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/SpencerBrown/mongodb-tls-certs/config"
	"github.com/SpencerBrown/mongodb-tls-certs/mx509"
	"log"
	"os"
	"path/filepath"
)

// createKeyCert writes a private key and cert file
// given filename, type of cert, parameters, signing key, and signing cert
// returns private key and certificate
func createKeyCert(certName string, configCert *config.Cert, CAkey crypto.PrivateKey, CACert *x509.Certificate) (crypto.PrivateKey, *x509.Certificate, error) {
	privateKey, err := createPrivateKey(certName, config.Config.ExtensionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating %s private key: %v", certName, err)
	}
	cert, err := createCert(configCert, privateKey, CAkey, CACert)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating %s certificate: %v", certName, err)
	}
	return privateKey, cert, nil
}

// createCertificateKeyFile writes a combination key/certificate PEM file
func createCertificateKeyFile(filename string, certificateKeyFilename string) error {
	KeyPEM, err := readFile(filename, config.Config.KeyExtension)
	if err != nil {
		return fmt.Errorf("error reading %s key file: %v", filename, err)
	}
	certPEM, err := readFile(filename, config.Config.CertExtension)
	if err != nil {
		return fmt.Errorf("error reading %s certificate file: %v", filename, err)
	}
	keyCertPEM := append(KeyPEM, certPEM...)
	err = writeFile(filename+"-"+certificateKeyFilename, config.Config.CertExtension, keyCertPEM, true)
	if err != nil {
		log.Fatalf("Error writing %s key/certificate file: %v", certificateKeyFilename, err)
	}
	return nil
}

// createCAFile writes a number of certificate files into one CAFile
func createCAFile(filenames []string, chainFilename string) error {
	CAFilePEM := make([]byte, 0, 2000)
	for _, filename := range filenames {
		CACertPEM, err := readFile(filename, config.Config.CertExtension)
		if err != nil {
			return fmt.Errorf("error reading %s cert file: %v", filename, err)
		}
		CAFilePEM = append(CAFilePEM, CACertPEM...)
	}
	err := writeFile(chainFilename, config.Config.CertExtension, CAFilePEM, false)
	if err != nil {
		return fmt.Errorf("error writing %s CAFile: %v", chainFilename, err)
	}
	return nil
}

// createKeyFile writes a keyfile
func createKeyFile() error {
	key := mx509.CreateKeyFile()
	err := writeFile(config.Config.KeyFile.Filename, config.Config.KeyExtension, key, true)
	if err != nil {
		return fmt.Errorf("error writing keyfile: %v", err)
	}
	return nil
}

// createPrivateKey creates private key and writes it to the file "filename.ext" in PEM format
func createPrivateKey(filename string, ext string) (crypto.PrivateKey, error) {
	key, PEMkey, err := mx509.CreatePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("error creating private key %v", err)
	}
	err = writeFile(filename, ext, PEMkey, true)
	if err != nil {
		return nil, fmt.Errorf("error writing private key file: %v", err)
	}
	return key, nil
}

func createCert(certName string, configCert *config.Cert, key crypto.PrivateKey, CAKey crypto.PrivateKey, CACert *x509.Certificate) (*x509.Certificate, error) {
	cert, PEMcert, err := mx509.CreateCert(configCert.Type, key, CAKey, CACert)
	if err != nil {
		return nil, fmt.Errorf("error creating %s certificate: %v", certName, err)
	}
	err = writeFile(certName, config.Config.ExtensionCert, PEMcert, false)
	if err != nil {
		return nil, fmt.Errorf("error writing %s certificate file: %v", certName, err)
	}
	return cert, nil
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
	tlsDirectory := config.Config.Directory
	err := os.MkdirAll(tlsDirectory, 0755)
	if err != nil {
		return fmt.Errorf("error creating directory %s: %v", tlsDirectory, err)
	}
	fn := prefix + "." + extension
	fn = filepath.Join(tlsDirectory, fn)
	perms := os.FileMode(0644)
	if private {
		perms = os.FileMode(0600)
	}
	err = os.WriteFile(fn, content, perms)
	if err != nil {
		return fmt.Errorf("error writing file %s: %v", fn, err)
	}
	log.Printf("'%s' file created", fn)
	return nil
}

// readFile reads <prefix>.<extension> and returns slice of bytes
func readFile(prefix string, extension string) ([]byte, error) {
	tlsDirectory := config.Config.Directory
	fn := prefix + "." + extension
	fn = filepath.Join(tlsDirectory, fn)
	content, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", fn, err)
	}
	return content, nil
}
