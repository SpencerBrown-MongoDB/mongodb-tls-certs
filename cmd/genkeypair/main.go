/*
 * from https://github.com/golang-samples/cipher/blob/master/crypto/rsa_keypair.go
 * Generates a private/public key pair in PEM format (not Certificate)
 *
 * The generated private key can be parsed with openssl as follows:
 * > openssl rsa -in key.pem -text
 *
 * The generated public key can be parsed as follows:
 * > openssl rsa -pubin -in pub.pem -text
 */
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func main() {
	// priv *rsa.PrivateKey
	// err error
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = priv.Validate()
	if err != nil {
		fmt.Println("Validation failed.", err)
	}

	// Get der format. priv_der []byte
	privDer := x509.MarshalPKCS1PrivateKey(priv)

	// pem.Block
	// blk pem.Block
	privBlk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}

	// Resultant private key in PEM format.
	// priv_pem string
	privPem := string(pem.EncodeToMemory(&privBlk))

	fmt.Printf(privPem)

	// Public Key generation

	pub := priv.PublicKey
	pubDer, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		fmt.Println("Failed to get der format for PublicKey.", err)
		return
	}

	pubBlk := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubDer,
	}
	pubPem := string(pem.EncodeToMemory(&pubBlk))
	fmt.Printf(pubPem)
}
