package pkcs8

import (
	"fmt"

	"github.com/youmark/pkcs8"

	"crypto/x509"
	"encoding/pem"
	"strings"
)

// GetPKCS8EncryptedKey decrypts a PKCS#8 encrypted private key using the given password.
func GetPKCS8EncryptedKey(priKeyBytes []byte, pemKeyPwd string) ([]byte, error) {
	// find private key block
	var priKeyBlock *pem.Block
	for {
		// Decode returns the next PEM block and any remaining bytes not decoded.
		priKeyBlock, priKeyBytes = pem.Decode(priKeyBytes)
		if priKeyBlock == nil {
			return nil, fmt.Errorf("Private key not found in TLS certificate file")
		}
		// The type of a PEM block is found at the beginning and end of the block
		// (i.e. -----BEGIN <HERE>-----)
		// The most relevant types are "PRIVATE KEY", "RSA PRIVATE KEY", "CERTIFICATE", "X509 Certificate"
		if priKeyBlock.Type == "PRIVATE KEY" || strings.HasSuffix(priKeyBlock.Type, " PRIVATE KEY") {
			break
		}
	}
	// decrypt the private key
	var decData []byte
	var err error
	if x509.IsEncryptedPEMBlock(priKeyBlock) {
		decData, err = x509.DecryptPEMBlock(priKeyBlock, []byte(pemKeyPwd))
		if err != nil {
			return nil, fmt.Errorf("Private key in TLS certificate could not be decrypted: %v", err)
		}
	} else if strings.Contains(priKeyBlock.Type, "ENCRYPTED") {
		// The pkcs8 package only handles the PKCS #5 v2.0 scheme.
		decrypted, err := pkcs8.ParsePKCS8PrivateKey(priKeyBlock.Bytes, []byte(pemKeyPwd))
		if err != nil {
			return nil, fmt.Errorf("pkcs8 private key couldn't be parsed: %v", err)
		}
		decData, err = x509.MarshalPKCS8PrivateKey(decrypted)
		if err != nil {
			return nil, fmt.Errorf("pkcs8 private key couldn't be decrypted: %v", err)
		}
	}
	// patch up the block to contain the decrypted data including removing headers
	// that say that the data was encrypted and how.
	priKeyBlock.Bytes = decData
	delete(priKeyBlock.Headers, "Proc-Type")
	delete(priKeyBlock.Headers, "DEK-Info")
	priKeyBytes = pem.EncodeToMemory(priKeyBlock)
	return priKeyBytes, nil
}
