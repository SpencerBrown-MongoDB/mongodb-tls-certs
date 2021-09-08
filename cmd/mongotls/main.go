package main

import (
	"flag"
	"fmt"
	"github.com/SpencerBrown/mongodb-tls-certs/config"
	"log"
)

func main() {

	var (
		configFilename = flag.String("f", "config/config.yaml", "Config file path/name")
	)
	flag.Parse()

	err := config.GetConfig(configFilename)

	if err != nil {
		log.Fatalf("Error getting config file '%s': %v", *configFilename, err)
	}

	err = createCerts()
	if err != nil {
		log.Fatalf("Error creating certificates: %v", err)
	}

	err = createCombos()
	if err != nil {
		log.Fatalf("Error creating combination files: %v", err)
	}

	//// Create Root CA key and certificate
	//rootCAKey, rootCACert, err := createKeyCert(config.RootCACert, nil, nil)
	//if err != nil {
	//	log.Fatalf("Error creating %s key/certificate: %v", config.Config.Certs[config.RootCACert].Filename, err)
	//}
	//
	//// Create Signing intermediate CA key and certificate
	//signingCAKey, signingCACert, err := createKeyCert(config.IntermediateCACert, rootCAKey, rootCACert)
	//if err != nil {
	//	log.Fatalf("Error creating %s key/certificate: %v", config.Config.Certs[config.IntermediateCACert].Filename, err)
	//}
	//
	//// create Server private key and certificate
	//_, _, err = createKeyCert(config.ServerCert, signingCAKey, signingCACert)
	//if err != nil {
	//	log.Fatalf("Error creating %s key/certificate: %v", config.Config.Certs[config.ServerCert].Filename, err)
	//}
	//
	//// create Client private key and certificate
	//_, _, err = createKeyCert(config.ClientCert, signingCAKey, signingCACert)
	//if err != nil {
	//	log.Fatalf("Error creating %s key/certificate: %v", config.Config.Certs[config.ClientCert].Filename, err)
	//}
	//
	//// create OCSP signing private key and certificate
	//_, _, err = createKeyCert(config.OCSPSigningCert, signingCAKey, signingCACert)
	//if err != nil {
	//	log.Fatalf("Error creating %s key/certificate: %v", config.Config.Certs[config.OCSPSigningCert].Filename, err)
	//}

	// Create the server's certificateKeyFile
	err = createCertificateKeyFile(config.Config.Certs[config.ServerCert].Filename, config.Config.Certs[config.CertificateKeyFile].Filename)
	if err != nil {
		log.Fatalf("Errir writing server certificateKeyFile: %v", err)
	}

	// Create the client's certificateKeyFile
	err = createCertificateKeyFile(config.Config.Certs[config.ClientCert].Filename, config.Config.Certs[config.CertificateKeyFile].Filename)
	if err != nil {
		log.Fatalf("Errir writing client certificateKeyFile: %v", err)
	}

	// Create the CAFile
	CAFiles := []string{config.Config.Certs[config.IntermediateCACert].Filename, config.Config.Certs[config.RootCACert].Filename}
	err = createCAFile(CAFiles, config.Config.Certs[config.CAFile].Filename)
	if err != nil {
		log.Fatalf("error writing CAFile: %v", err)
	}

	// Create a keyfile; can be used for local encryption key or replica set authentication keyfile
	err = createKeyFile()
	if err != nil {
		log.Fatalf("Error writing keyfile: %v", err)
	}
}

func createCerts() error {

	// Walk through configuration for certificates and create each key/certificate pair
	// Multiple passes will be done until all certificates are created

	var err error
	allCreated := false
	for !allCreated {
		allCreated = true
		for certName, cert := range config.Config.Certificates {
			if cert.Certificate == nil {
				if cert.Type == config.RootCACert {
					// self-signed, just create it
					cert.PrivateKey, cert.Certificate, err = createKeyCert(certName, &cert, nil, nil)
					if err != nil {
						return fmt.Errorf("error creating certificate %s: %v", certName, err)
					}
				} else {
					// not self-signed, check if issuer created yet
					issuerCert := config.Config.Certificates[cert.Issuer]
					if issuerCert.Certificate == nil {
						allCreated = false // this one has to wait until its issuer is created
					} else {
						cert.PrivateKey, cert.Certificate, err = createKeyCert(certName, &cert, issuerCert.PrivateKey, issuerCert.Certificate)
					}
				}
			}
		}
	}
	return nil
}

func createCombos() error {
	if config.Config.Combos == nil {
		return nil // nothing to do
	}
	for comboName, comboList := range config.Config.Combos {
		err := createCombo(comboName, comboList)
		if err != nil {
			return fmt.Errorf("error creating combo file '%s': %v", comboName, err)
		}
	}
	return nil
}
