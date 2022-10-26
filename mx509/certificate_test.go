package mx509

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func TestCreateCert(t *testing.T) {
	rcertInfo := CertInfo{
		CertType:  RootCACert,
		ValidDays: 42,
		O:         "Otest",
		OU:        "OUtest",
		CN:        "CNtest",
		Hosts:     nil,
	}
	// test a root CA
	rpriv, _, _, err := CreatePrivateKey(2048, false)
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
		CertType:  ServerCert,
		ValidDays: 24,
		O:         "Otest",
		OU:        "OUtest",
		CN:        "CNtest",
		Hosts:     []string{"example.com"},
	}
	spriv, _, _, err := CreatePrivateKey(2048, false)
	if err != nil {
		t.Errorf("error creating server private key: %v", err)
	}
	scert, scertPEM, err := CreateCert(&scertInfo, spriv, rpriv, rcert)
	if err != nil {
		t.Errorf("error creating server certificate: %v", err)
	}
	checkCert(t, scert, scertPEM)
}

func TestCreateCSR(t *testing.T) {
	csrCertInfo := CertInfo{
		CertType: ClientCert,
		O:        "Otest",
		OU:       "OUtest",
		CN:       "CNtest",
	}
	csrpriv, _, _, err := CreatePrivateKey(4096, false)
	if err != nil {
		t.Fatalf("error creating private key for CSR: %v", err)
	}
	csrPEM, err := CreateCSR(&csrCertInfo, csrpriv)
	if err != nil {
		t.Fatalf("error creating Certificate Request: %v", err)
	}
	checkCSR(t, csrPEM)
}

func checkCert(t *testing.T, cert *x509.Certificate, certPEM []byte) {
	cert2, err := GetCertificate(certPEM)
	if err != nil {
		t.Fatalf("error parsing PEM certificate: %v", err)
	}
	if !reflect.DeepEqual(cert, cert2) {
		t.Errorf("got: %v, want: %v", cert, cert2)
	}
}

func checkCSR(t *testing.T, csrPEM []byte) {
	csr2, err := GetCSR(csrPEM)
	if err != nil {
		t.Fatalf("error parsing PEM CSR: %v", err)
	}
	if err = csr2.CheckSignature(); err != nil {
		t.Errorf("error checking CSR signature: %v", err)
	}
}
