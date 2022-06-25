package mx509

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func CreateSSHKeyPair(rsabits int) (pub ssh.PublicKey, pubBytes []byte, priv crypto.PrivateKey, privPEM []byte, err error) {
	priv, privPEM, err = CreatePrivateKey(rsabits)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error creating private SSH key: %v", err)
	}
	pub, err = ssh.NewPublicKey(&(priv.(*rsa.PrivateKey)).PublicKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error creating public SSH key: %v", err)
	}
	pubBytes = ssh.MarshalAuthorizedKey(pub)
	return
}
