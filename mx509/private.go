package mx509

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// CreatePrivateKey returns a PKCS#8 formatted private key which is not encrypted
// it is an RSA private key of the specified length.
// it is returned as a pointer to an rsa.PrivateKey,
// and also in PEM format as a byte slice.
func CreatePrivateKey(rsabits int) (crypto.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsabits)
	if err != nil {
		return nil, nil, err
	}
	err = key.Validate()
	if err != nil {
		return nil, nil, err
	}
	privDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	privBlk := pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}
	return key, pem.EncodeToMemory(&privBlk), nil
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
