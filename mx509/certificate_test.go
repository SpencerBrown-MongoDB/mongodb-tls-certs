package mx509

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func TestCreateCert(t *testing.T) {
	rcertInfo := CertInfo{
		CertType: RootCACert,
		O:        "Otest",
		OU:       "OUtest",
		CN:       "CNtest",
		Hosts:    nil,
	}
	// test a root CA
	rpriv, _, err := CreatePrivateKey()
	if err != nil {
		t.Errorf("error creating root CA private key: %v", err)
	}
	rcert, rcertPEM, err := CreateCert(&rcertInfo, rpriv, nil, nil)
	if err != nil {
		t.Errorf("error creating root CA certificate: %v", err)
	}
	checkCert(t, rcert, rcertPEM)
	// test a server cert
	scertInfo := CertInfo{
		CertType: ServerCert,
		O:        "Otest",
		OU:       "OUtest",
		CN:       "CNtest",
		Hosts:    []string{"example.com"},
	}
	spriv, _, err := CreatePrivateKey()
	if err != nil {
		t.Errorf("error creating server private key: %v", err)
	}
	scert, scertPEM, err := CreateCert(&scertInfo, spriv, rpriv, rcert)
	checkCert(t, scert, scertPEM)
}

func checkCert(t *testing.T, cert *x509.Certificate, certPEM []byte) {
	cert2, err := GetCertificate(certPEM)
	if err != nil {
		t.Errorf("error parsing PEM certificate: %v", err)
	}
	if !reflect.DeepEqual(cert, cert2) {
		t.Errorf("got: %v, want: %v", cert, cert2)
	}
}
