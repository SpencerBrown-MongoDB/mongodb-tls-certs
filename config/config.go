package config

//package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

const ( // Certificate types
	RootCACert = iota
	IntermediateCACert
	OCSPSigningCert
	ServerCert
	ClientCert
)

const (
	defaultPublicDirectory  = "tls"
	defaultPrivateDirectory = "tls/private"
	defaultExtensionKey     = "key"
	defaultExtensionCert    = "pem"
)

type Cert struct {
	// Filled in by YAML unmarshalling
	TypeString string `yaml:"type"`
	Issuer     string `yaml:"issuer"`
	Subject    struct {
		O  string `yaml:"O"`
		OU string `yaml:"OU"`
		CN string `yaml:"CN"`
	}
	Hosts []string `yaml:"hosts"`
	// Created programmatically
	Type        int               `yaml:"-"`
	PrivateKey  crypto.PrivateKey `yaml:"-"`
	Certificate *x509.Certificate `yaml:"-"`
}

type Type struct {
	// filled in by YAML unmarshalling
	Directories  map[string]string   `yaml:"directories"`
	Extensions   map[string]string   `yaml:"extensions"`
	KeyFiles     []string            `yaml:"keyfiles"`
	Certificates map[string]Cert     `yaml:"certificates"`
	Combos       map[string][]string `yaml:"combos"`
	// filled in programmatically
	PublicDirectory  string `yaml:"-"`
	PrivateDirectory string `yaml:"-"`
	ExtensionKey     string `yaml:"-"`
	ExtensionCert    string `yaml:"-"`
}

// Config is a global variable for THE CONFIG, there will only be one per run
var Config Type

func GetConfig(configFilename *string) error {
	configFile, err := os.ReadFile(filepath.Clean(*configFilename))
	if err != nil {
		return fmt.Errorf("error reading config file '%s': %v", *configFilename, err)
	}
	err = yaml.Unmarshal(configFile, &Config)
	if err != nil {
		return fmt.Errorf("error parsing YAML config file '%s': %v", *configFilename, err)
	}

	Config.PublicDirectory = defaultPublicDirectory
	Config.PrivateDirectory = defaultPrivateDirectory
	if Config.Directories != nil {
		for dirName, dir := range Config.Directories {
			switch dirName {
			case "public":
				Config.PublicDirectory = dir
			case "private":
				Config.PrivateDirectory = dir
			default:
				return fmt.Errorf("invalid entry %s in directories section of config file %s", dirName, *configFilename)
			}
		}
	}

	Config.ExtensionKey = defaultExtensionKey
	Config.ExtensionCert = defaultExtensionCert
	if Config.Extensions != nil {
		for extName, ext := range Config.Extensions {
			switch extName {
			case "key":
				Config.ExtensionKey = ext
			case "certificate":
				Config.ExtensionCert = ext
			default:
				return fmt.Errorf("invalid entry %s in extensions section of config file %s", extName, ext)
			}
		}
	}

	// Do some checking on the certificate configurations
	for certName, cert := range Config.Certificates {
		switch cert.TypeString {
		case "RootCA":
			cert.Type = RootCACert
		case "IntermediateCA":
			cert.Type = IntermediateCACert
		case "OCSPSigning":
			cert.Type = OCSPSigningCert
		case "server":
			cert.Type = ServerCert
		case "client":
			cert.Type = ClientCert
		default:
			return fmt.Errorf("invalid type %s for certificate %s", certName, cert.TypeString)
		}
		if cert.Type == RootCACert {
			if cert.Issuer != "" {
				return fmt.Errorf("self-signed certificate %s must not have issuer", certName)
			}
		} else {
			issuerCert, ok := Config.Certificates[cert.Issuer]
			if !ok {
				return fmt.Errorf("certificate %s has missing issuer %s", certName, cert.Issuer)
			} else {
				if issuerCert.TypeString != "RootCA" && issuerCert.TypeString != "IntermediateCA" {
					return fmt.Errorf("certificate %s has issuer %s that is not a CA", certName, cert.Issuer)
				}
			}
		}
	}
	return nil
}

//func main() {
//	cfn := "config/config.yaml"
//	err := GetConfig(&cfn)
//	if err != nil {
//		log.Fatalf("Error getting config: %v", err)
//	}
//	fmt.Printf("config: %#v\n", Config)
//	fmt.Printf("server: %#v\n", Config.Certificates["server"])
//}
