package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/SpencerBrown/mongodb-tls-certs/config"
	"github.com/SpencerBrown/mongodb-tls-certs/mx509"
)

// createKeyCert writes a private key and cert file
// given filename, type of cert, parameters, signing key, and signing cert
// returns private key and certificate
func createKeyCert(certName string, configCert *config.Cert, CAkey crypto.PrivateKey, CACert *x509.Certificate) (crypto.PrivateKey, *x509.Certificate, error) {
	privateKey, err := createPrivateKey(certName, config.Config.ExtensionKey, configCert.RSABits)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating %s private key: %v", certName, err)
	}
	cert, err := createCert(certName, configCert, privateKey, CAkey, CACert)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating %s certificate: %v", certName, err)
	}
	return privateKey, cert, nil
}

// createCombo creates a combo file by concatenating a list of PEM files and writing it as a single file
func createCombo(comboName string, comboList []string) error {
	comboPEM := make([]byte, 0)
	isAnyPrivate := false
	for _, fnext := range comboList {
		isPrivate := false
		ext := filepath.Ext(fnext)
		if ext == "" {
			return fmt.Errorf("error: filename '%s' has no extension", fnext)
		}
		ext = ext[1:]
		if ext == config.Config.ExtensionKey {
			isPrivate = true
			isAnyPrivate = true
		}
		name := fnext[:len(fnext)-len(ext)-1]
		thisPEM, err := readFile(name, ext, isPrivate)
		if err != nil {
			return fmt.Errorf("error reading file '%s': %v", fnext, err)
		}
		comboPEM = append(comboPEM, thisPEM...)
	}
	err := writeFile(comboName, config.Config.ExtensionCert, comboPEM, isAnyPrivate)
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

// createSSHKeyPair creates an SSH keypair and writes it to the file "filename" and "filename.pub"
func createSSHKeyPair(filename string, rsabits int) error {
	_, pubBytes, _, privPEM, err := mx509.CreateSSHKeyPair(rsabits)
	err = writeFile(filename, config.Config.ExtensionSSHKey, privPEM, true)
	if err != nil {
		return fmt.Errorf("error writing private SSH key file '%s': %v", filename, err)
	}
	err = writeFile(filename, config.Config.ExtensionSSHPub, pubBytes, false)
	if err != nil {
		return fmt.Errorf("error writing public SSH key file '%s': %v", filename, err)
	}
	return nil
}

// createPrivateKey creates private key and writes it to the file "filename.ext" in PEM format
func createPrivateKey(filename string, ext string, rsaBits int) (crypto.PrivateKey, error) {
	key, PEMkey, err := mx509.CreatePrivateKey(rsaBits)
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
		CertType:  configCert.Type,
		ValidDays: configCert.ValidDays,
		O:         configCert.Subject.O,
		OU:        configCert.Subject.OU,
		CN:        configCert.Subject.CN,
		Hosts:     configCert.Hosts,
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
	content, err := readFile(prefix, extension, true)
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
	content, err := readFile(prefix, extension, false)
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
	fileName, fileExists := getFilePaths(prefix, extension, private)
	if fileExists {
		log.Printf("File '%s' already exists", fileName)
		return nil
	}
	var perms fs.FileMode
	if private {
		perms = os.FileMode(0600)
	} else {
		perms = os.FileMode(0644)
	}
	err := os.WriteFile(fileName, content, perms)
	if err != nil {
		return fmt.Errorf("error writing file %s: %v", fileName, err)
	}
	log.Printf("'%s' file created", fileName)
	return nil
}

// readFile reads <prefix>.<extension> and returns slice of bytes
func readFile(prefix string, extension string, private bool) ([]byte, error) {
	fileName, exists := getFilePaths(prefix, extension, private)
	if !exists {
		return nil, fmt.Errorf("file '%s' does not exist", fileName)
	}
	content, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", fileName, err)
	}
	return content, nil
}

// getFilePaths figures out and returns what directories and filename to actually use
// if the prefix has a directory path, use it
// if the extension is the keyfile extension (default "key") OR the private bit is true, use the private directory
// otherwise, use the public directory
func getFilePaths(prefix string, extension string, private bool) (fileName string, exists bool) {
	prefixDir := filepath.Dir(prefix)
	prefixBase := filepath.Base(prefix)
	var thisDir string
	if len(prefixDir) > 1 {
		thisDir = prefixDir
	} else if private {
		thisDir = config.Config.PrivateDirectory
	} else {
		thisDir = config.Config.PublicDirectory
	}
	if extension == "" {
		fileName = prefixBase
	} else {
		fileName = prefixBase + "." + extension
	}
	os.MkdirAll(thisDir, 0755)
	fileName = filepath.Join(thisDir, fileName)
	_, err := os.Stat(fileName)
	switch err {
	case os.ErrNotExist:
		exists = false
	case nil:
		exists = true
	default:
		exists = false
	}
	return
}

// removeFiles erases all files in the public and private directories
func removeFiles() error {
	var err error
	_, err = os.Stat(config.Config.PrivateDirectory)
	if !os.IsNotExist(err) {
		err = os.RemoveAll(config.Config.PrivateDirectory)
		if err != nil {
			return fmt.Errorf("error removing private directory '%s': %v", config.Config.PrivateDirectory, err)
		}
	}
	_, err = os.Stat(config.Config.PublicDirectory)
	if !os.IsNotExist(err) {
		err = os.RemoveAll(config.Config.PublicDirectory)
		if err != nil {
			return fmt.Errorf("error removing public directory '%s': %v", config.Config.PublicDirectory, err)
		}
	}
	return nil
}
