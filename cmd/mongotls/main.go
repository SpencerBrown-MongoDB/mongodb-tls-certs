package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/SpencerBrown-MongoDB/mongodb-tls-certs/config"
)

func main() {

	var (
		versionp       = flag.Bool("version", false, "Print version and exit")
		configFilename = flag.String("f", "mongodb-tls.yaml", "Config file path/name")
		replaceFilesP  = flag.Bool("erase", false, "Erase all files from directories before generating new ones")
	)
	flag.Parse()

	if *versionp {
		fmt.Println(version())
		return
	}

	config.Options.ReplaceFiles = *replaceFilesP

	err := config.GetConfig(configFilename)

	if err != nil {
		log.Fatalf("Error getting config file '%s': %v", *configFilename, err)
	}

	if *replaceFilesP {
		log.Printf("Erasing all files in public directory '%s' and private directory '%s'", config.Config.PublicDirectory, config.Config.PrivateDirectory)
		err = removeFiles()
		if err != nil {
			log.Fatalf("Error erasing files: %v", err)
		}
	}

	err = createCerts()
	if err != nil {
		log.Fatalf("Error creating certificates: %v", err)
	}

	err = createSSHKeyPairs()
	if err != nil {
		log.Fatalf("Error creating SSH keys: %v", err)
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
						return fmt.Errorf("error creating self-signed certificate/key %s: %v", certName, err)
					}
				} else {
					// not self-signed, check if issuer created yet
					if cert.IssuerCert.Certificate == nil {
						allCreated = false // this one has to wait until its issuer is created
					} else {
						cert.PrivateKey, cert.Certificate, err = createKeyCert(certName, cert, cert.IssuerCert.PrivateKey, cert.IssuerCert.Certificate)
						if err != nil {
							return fmt.Errorf("error creating certificate/key %s: %v", certName, err)
						}
					}
				}
			}
		}
	}
	return nil
}

func createCombos() error {
	for comboName, comboList := range config.Config.Combos {
		err := createCombo(comboName, comboList)
		if err != nil {
			return fmt.Errorf("error creating combo file '%s': %v", comboName, err)
		}
	}
	return nil
}

func createKeyFiles() error {
	for keyfileName := range config.Config.KeyFiles {
		err := createKeyFile(keyfileName)
		if err != nil {
			log.Fatalf("Error creating keyfile '%s': %v", keyfileName, err)
		}
	}
	return nil
}

func createSSHKeyPairs() error {
	for sshKeyName, sshKeyPair := range config.Config.SSHKeyPairs {
		err := createSSHKeyPair(sshKeyName, sshKeyPair.RSABits)
		if err != nil {
			log.Fatalf("Error creating SSH keypair '%s': %v", sshKeyName, err)
		}
	}
	return nil
}
