package main

import (
	"flag"
	"fmt"
	"github.com/SpencerBrown/mongodb-tls-certs/config"
	"log"
)

func main() {

	var (
		configFilename = flag.String("f", "mongodb-tls.yaml", "Config file path/name")
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

	err = createKeyFiles()
	if err != nil {
		log.Fatalf("Error creating keyfiles: %v", err)
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
					cert.PrivateKey, cert.Certificate, err = createKeyCert(certName, cert, nil, nil)
					if err != nil {
						return fmt.Errorf("error creating certificate %s: %v", certName, err)
					}
				} else {
					// not self-signed, check if issuer created yet
					issuerCert := config.Config.Certificates[cert.Issuer]
					if issuerCert.Certificate == nil {
						allCreated = false // this one has to wait until its issuer is created
					} else {
						cert.PrivateKey, cert.Certificate, err = createKeyCert(certName, cert, issuerCert.PrivateKey, issuerCert.Certificate)
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

func createKeyFiles() error {
	for _, fn := range config.Config.KeyFiles {
		err := createKeyFile(fn)
		if err != nil {
			log.Fatalf("Error creating keyfile '%s': %v", fn, err)
		}
	}
	return nil
}
