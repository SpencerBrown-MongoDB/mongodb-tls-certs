package main

import (
	"github.com/SpencerBrown/mongodb-tls-certs/mx509"
	"log"
)

func main() {

	_ = options()

	// Create Root CA key and certificate
	rootCAKey, rootCACert, err := createKeyCert(mx509.CreateRootCACert, rootCAFilename, &rootCAParms, nil, nil)
	if err != nil {
		log.Fatalf("Error creating %s key/certificate: %v", rootCAFilename, err)
	}

	// Create Signing intermediate CA key and certificate
	signingCAKey, signingCACert, err := createKeyCert(mx509.CreateIntermediateCACert, signingCAFilename, &signingCAParms, rootCAKey, rootCACert)
	if err != nil {
		log.Fatalf("Error creating %s key/certificate: %v", signingCAFilename, err)
	}

	// create Server private key and certificate
	_, _, err = createKeyCert(mx509.CreateServerCert, serverFilename, &serverCAParms, signingCAKey, signingCACert)
	if err != nil {
		log.Fatalf("Error creating %s key/certificate: %v", serverFilename, err)
	}

	// create Client private key and certificate
	_, _, err = createKeyCert(mx509.CreateClientCert, clientFilename, &clientCAParms, signingCAKey, signingCACert)
	if err != nil {
		log.Fatalf("Error creating %s key/certificate: %v", clientFilename, err)
	}

	// create OCSP signing private key and certificate
	_, _, err = createKeyCert(mx509.CreateOCSPSigningCert, OCSPSigningFilename, &OCSPSigningParms, signingCAKey, signingCACert)
	if err != nil {
		log.Fatalf("Error creating %s key/certificate: %v", OCSPSigningFilename, err)
	}

	// Create the server's certificateKeyFile
	err = createCertificateKeyFile(serverFilename, certificateKeyFilename)
	if err != nil {
		log.Fatalf("Errir writing server certificateKeyFile: %v", err)
	}

	// Create the client's certificateKeyFile
	err = createCertificateKeyFile(clientFilename, certificateKeyFilename)
	if err != nil {
		log.Fatalf("Errir writing client certificateKeyFile: %v", err)
	}

	// Create the CAFile
	CAFiles := []string{signingCAFilename, rootCAFilename}
	err = createCAFile(CAFiles, CAFileFilename)
	if err != nil {
		log.Fatalf("error writing CAFile: %v", err)
	}

	// Create a keyfile; can be used for local encryption key or replica set authentication keyfile
	err = createKeyFile(KeyFileFilename)
	if err != nil {
		log.Fatalf("Error writing keyfile: %v", err)
	}
}
