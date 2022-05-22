package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/SpencerBrown/mongodb-tls-certs/config"
)

func main() {

	var (
		versionp       = flag.Bool("version", false, "Print version and exit")
		configFilename = flag.String("f", "mongodb-tls.yaml", "Config file path/name")
	)
	flag.Parse()

	if *versionp {
		fmt.Println(version())
		return
	}

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
				if cert.IsSelfSigned {
					// self-signed, just create it
					cert.PrivateKey, cert.Certificate, err = createKeyCert(certName, cert, nil, nil)
					if err != nil {
						return fmt.Errorf("error creating self-signed certificate %s: %v", certName, err)
					}
				} else {
					// not self-signed, check if issuer created yet
					if cert.IssuerCert.Certificate == nil {
						allCreated = false // this one has to wait until its issuer is created
					} else {
						cert.PrivateKey, cert.Certificate, err = createKeyCert(certName, cert, cert.IssuerCert.PrivateKey, cert.IssuerCert.Certificate)
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
