package mx509

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// CreatePrivateKey returns a PKCS#8 formatted private key which is not encrypted
// it is an RSA 2048-bit private key.
// it is returned as a pointer to an rsa.PrivateKey,
// and also in PEM format as a byte slice.
func CreatePrivateKey() (crypto.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
