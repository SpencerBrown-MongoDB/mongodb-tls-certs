package config

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SpencerBrown-MongoDB/mongodb-tls-certs/mx509"
	"gopkg.in/yaml.v3"
)

// defaults for directories and extensions
const (
	defaultPublicDirectory  = "tls"
	defaultPrivateDirectory = "tls/private"
	defaultExtensionKey     = "key"
	defaultExtensionCert    = "pem"
	defaultExtensionSSHKey  = ""
	defaultExtensionSSHPub  = "pub"
	defaultExtensionSSHCert = "cer"
)

// default for RSA key bit length
const defaultRSABits = 2048

// default for number of days certificate is valid
const defaultValidDays = 90

// certInfo is information about a certificate
type certInfo struct {
	ctype        int  // certificate type
	validDays    int  // How many days to ve valid?
	rsaBits      int  // How many bits for RSA key?
	isCA         bool // is it a CA?
	isSelfSigned bool // is it self-signed?
	isOCSPSigner bool // Is it an OCSP signer?
}

// SubjectType is the type for a subject name
type SubjectType struct {
	O  string `yaml:"O"`
	OU string `yaml:"OU"`
	CN string `yaml:"CN"`
}

// getCertType converts a type string to information about the kind of certificate it is
func getCertType(typeString string) (*certInfo, error) {
	theMap := map[string]certInfo{
		"rootCA":         {mx509.RootCACert, 0, 0, true, true, false},
		"intermediateCA": {mx509.IntermediateCACert, 0, 0, true, false, false},
		"OCSPSigning":    {mx509.OCSPSigningCert, 0, 0, false, false, true},
		"server":         {mx509.ServerCert, 0, 0, false, false, false},
		"client":         {mx509.ClientCert, 0, 0, false, false, false},
	}
	certType, ok := theMap[typeString]
	if ok {
		return &certType, nil
	} else {
		return nil, fmt.Errorf("invalid certificate type '%s'", typeString)
	}
}

// Cert type is an Internal representation of a certificate specification,
// some filled in from the YAML config file, some calculated
type Cert struct {
	// Filled in by YAML unmarshalling
	TypeString string `yaml:"type"`
	ValidDays  int    `yaml:"valid"`
	Encrypt    bool   `yaml:"encrypt"`
	Issuer     string `yaml:"issuer"`
	Subject    SubjectType
	Hosts      []string `yaml:"hosts"`
	RSABits    int      `yaml:"rsabits"`
	// Created programmatically
	Type         int               `yaml:"-"`
	IsCA         bool              `yaml:"-"`
	IsSelfSigned bool              `yaml:"-"`
	IsOCSPSigner bool              `yaml:"-"`
	PrivateKey   crypto.PrivateKey `yaml:"-"`
	Certificate  *x509.Certificate `yaml:"-"`
	IssuerCert   *Cert             `yaml:"-"`
}

// SSHKeyPair type represents a request for SSH keys.
type SSHKeyPair struct {
	RSABits int `yaml:"rsabits"`
}

// KeyFile type represents a request for a keyfile, which is a random 32 binary bytes converted to base64 text
type KeyFile struct {
}

// ConfigT type is the internal representation of the entire config file,
// some filled in from the YAML config files, some calculated
type ConfigT struct {
	// filled in by YAML unmarshalling
	Directories  map[string]string `yaml:"directories"`
	Extensions   map[string]string `yaml:"extensions"`
	Subject      SubjectType
	KeyFiles     map[string]*KeyFile    `yaml:"keyfiles"`
	Certificates map[string]*Cert       `yaml:"certificates"`
	SSHKeyPairs  map[string]*SSHKeyPair `yaml:"sshkeypairs"`
	Combos       map[string][]string    `yaml:"combos"`
	// filled in programmatically
	PublicDirectory  string `yaml:"-"`
	PrivateDirectory string `yaml:"-"`
	ExtensionKey     string `yaml:"-"`
	ExtensionCert    string `yaml:"-"`
	ExtensionSSHKey  string `yaml:"-"`
	ExtensionSSHPub  string `yaml:"-"`
	ExtensionSSHCert string `yaml:"-"`
}

// Config is a global variable for "THE CONFIG", there will only be one per run
var Config ConfigT

// OptionsT type represents the options for this run
type OptionsT struct {
	ReplaceFiles bool
}

// Options is the global variable for the specified options for this run
var Options OptionsT

// GetConfig is responsible for parsing the YAML file and filling in the global variable Config
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
	Config.ExtensionSSHKey = defaultExtensionSSHKey
	Config.ExtensionSSHPub = defaultExtensionSSHPub
	Config.ExtensionSSHCert = defaultExtensionSSHCert
	if Config.Extensions != nil {
		for extName, ext := range Config.Extensions {
			switch extName {
			case "key":
				Config.ExtensionKey = ext
			case "certificate":
				Config.ExtensionCert = ext
			case "sshkey":
				Config.ExtensionSSHKey = ext
			case "sshpub":
				Config.ExtensionSSHPub = ext
			case "sshcert":
				Config.ExtensionSSHCert = ext
			default:
				return fmt.Errorf("invalid entry %s in extensions section of config file %s", extName, ext)
			}
		}
	}

	// Set default RSA bits for SSH key pairs if not specified
	for sshKeyPairName, sshKeyPair := range Config.SSHKeyPairs {
		if sshKeyPair == nil {
			Config.SSHKeyPairs[sshKeyPairName] = &SSHKeyPair{
				RSABits: defaultRSABits,
			}
		}
	}

	// Do some setup on the certificate configurations
	// - fill in the Type, IsSelfSigned, and IsCA field for each certificate
	// - fill in default subject fields
	// - fill in default number of days valid
	// - fill in default RSA key size
	// - make sure self-signed certs don't have issuer
	// - fill in issuer pointer for cert's issuer
	// - make sure issuer-signed certs have an issuer that is a CA
	for certName, cert := range Config.Certificates {
		certType, err := getCertType(cert.TypeString)
		if err != nil {
			return fmt.Errorf("invalid type %s for certificate %s", certName, cert.TypeString)
		}
		cert.Type = certType.ctype
		cert.IsCA = certType.isCA
		cert.IsSelfSigned = certType.isSelfSigned
		cert.IsOCSPSigner = certType.isOCSPSigner
		if cert.ValidDays == 0 {
			cert.ValidDays = defaultValidDays
		}
		if cert.RSABits == 0 {
			cert.RSABits = defaultRSABits
		}
		if cert.Subject.O == "" {
			cert.Subject.O = Config.Subject.O
		}
		if cert.Subject.OU == "" {
			cert.Subject.OU = Config.Subject.OU
		}
		if cert.Subject.CN == "" {
			cert.Subject.CN = Config.Subject.CN
		}
	}
	for certName, cert := range Config.Certificates {
		if cert.IsSelfSigned {
			if cert.Issuer != "" {
				return fmt.Errorf("self-signed certificate %s must not have issuer", certName)
			}
		} else {
			issuerCert, ok := Config.Certificates[cert.Issuer]
			cert.IssuerCert = issuerCert
			if !ok {
				return fmt.Errorf("certificate %s has missing issuer %s", certName, cert.Issuer)
			} else {
				if !issuerCert.IsCA {
					return fmt.Errorf("certificate %s has issuer %s that is not a CA", certName, cert.Issuer)
				}
			}
		}
	}
	return nil
}
