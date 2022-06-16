package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/SpencerBrown/mongodb-tls-certs/config"
	"github.com/SpencerBrown/mongodb-tls-certs/mx509"
	"golang.org/x/crypto/ssh"
)

// createKeyCert writes a private key and cert file
// given filename, type of cert, parameters, signing key, and signing cert
// returns private key and certificate
func createKeyCert(certName string, configCert *config.Cert, CAkey crypto.PrivateKey, CACert *x509.Certificate) (crypto.PrivateKey, *x509.Certificate, error) {
	privateKey, err := createPrivateKey(certName, config.Config.ExtensionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating %s private key: %v", certName, err)
	}
	cert, err := createCert(certName, configCert, privateKey, CAkey, CACert)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating %s certificate: %v", certName, err)
	}
	return privateKey, cert, nil
}

// createCombo creates a combo file by concatening a list of PEM files and writing it as a single file
func createCombo(comboName string, comboList []string) error {
	comboPEM := make([]byte, 0)
	isPrivate := false
	for _, fnext := range comboList {
		ext := filepath.Ext(fnext)
		if ext == "" {
			return fmt.Errorf("error: filename '%s' has no extension", fnext)
		}
		ext = ext[1:]
		if ext == config.Config.ExtensionKey {
			isPrivate = true
		}
		name := fnext[:len(fnext)-len(ext)-1]
		thisPEM, err := readFile(name, ext)
		if err != nil {
			return fmt.Errorf("error reading file '%s': %v", fnext, err)
		}
		comboPEM = append(comboPEM, thisPEM...)
	}
	err := writeFile(comboName, config.Config.ExtensionCert, comboPEM, isPrivate)
	if err != nil {
		return fmt.Errorf("error writing combo file '%s': %v", comboName, err)
	}
	return nil
}

// createKeyFile creates and writes a keyfile
func createKeyFile(filename string) error {
	key := mx509.CreateKeyFile()
	err := writeFile(filename, config.Config.ExtensionKey, key, true)
	if err != nil {
		return fmt.Errorf("error writing keyfile '%s': %v", filename, err)
	}
	return nil
}

// createSSHKey creates an SSH keypair and writes it to the file "filename" and "filename.pub"
func createSSHKey(filename string) error {
	key, PEMkey, err := mx509.CreatePrivateKey()
	if err != nil {
		return fmt.Errorf("error creating private SSH key: %v", err)
	}
	err = writeFile(filename, "", PEMkey, true)
	if err != nil {
		return fmt.Errorf("error writing private SSH key file '%s': %v", filename, err)
	}

	publicSSHKey, err := ssh.NewPublicKey(&(key.(*rsa.PrivateKey)).PublicKey)
	if err != nil {
		return fmt.Errorf("error creating public SSH key: %v", err)
	}
	publicSSHKeyBytes := ssh.MarshalAuthorizedKey(publicSSHKey)
	err = writeFile(filename, "pub", publicSSHKeyBytes, false)
	if err != nil {
		return fmt.Errorf("error writing public SSH key file '%s': %v", filename, err)
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

// createCert creates a signed certificate and writes it to the file
func createCert(certName string, configCert *config.Cert, key crypto.PrivateKey, CAKey crypto.PrivateKey, CACert *x509.Certificate) (*x509.Certificate, error) {
	certInfo := mx509.CertInfo{
		CertType: configCert.Type,
		O:        configCert.Subject.O,
		OU:       configCert.Subject.OU,
		CN:       configCert.Subject.CN,
		Hosts:    configCert.Hosts,
	}
	cert, PEMcert, err := mx509.CreateCert(&certInfo, key, CAKey, CACert)
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
	prefixDir := filepath.Dir(prefix)
	prefixBase := filepath.Base(prefix)
	publicDir := filepath.Join(config.Config.PublicDirectory, prefixDir)
	privateDir := filepath.Join(config.Config.PrivateDirectory, prefixDir)
	err := os.MkdirAll(publicDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating public directory %s: %v", publicDir, err)
	}
	err = os.MkdirAll(privateDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating private directory %s: %v", privateDir, err)
	}
	var fn string
	if extension == "" {
		fn = prefixBase
	} else {
		fn = prefixBase + "." + extension
	}
	var perms fs.FileMode
	if private {
		fn = filepath.Join(privateDir, fn)
		perms = os.FileMode(0600)
	} else {
		fn = filepath.Join(publicDir, fn)
		perms = os.FileMode(0644)
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
	prefixDir := filepath.Dir(prefix)
	prefixBase := filepath.Base(prefix)
	publicDir := filepath.Join(config.Config.PublicDirectory, prefixDir)
	privateDir := filepath.Join(config.Config.PrivateDirectory, prefixDir)
	var readDir string
	switch extension {
	case config.Config.ExtensionCert:
		readDir = publicDir
	case config.Config.ExtensionKey:
		readDir = privateDir
	default:
		return nil, fmt.Errorf("file extension not recognized: %s", extension)
	}
	fn := filepath.Join(readDir, prefixBase+"."+extension)
	content, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", fn, err)
	}
	return content, nil
}
