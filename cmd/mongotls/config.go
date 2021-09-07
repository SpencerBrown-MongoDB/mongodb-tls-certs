package main

import (
	"flag"
	"github.com/SpencerBrown/mongodb-tls-certs/mx509"
	"net"
	"strings"
)

const defaultHost = "mongodb-local.computer"

const tlsDirectory = "tls"

const (
	rootCAFilename         = "root-ca"
	signingCAFilename      = "signing-ca"
	OCSPSigningFilename    = "ocsp"
	serverFilename         = "server"
	clientFilename         = "client"
	certificateKeyFilename = "key-cert"
	CAFileFilename         = "ca-chain"
	KeyFileFilename        = "keyfile"
)

const (
	certExtension = "pem"
	keyExtension  = "key"
)

var rootCAParms = mx509.CertParameters{
	O:  "MongoDB",
	OU: "Root CA",
	CN: "Repro",
}

var signingCAParms = mx509.CertParameters{
	O:  "MongoDB",
	OU: "Signing CA",
	CN: "Repro",
}

var OCSPSigningParms = mx509.CertParameters{
	O:  "MongoDB",
	OU: "OCSP Response Signing",
	CN: "Repro",
}

var serverCAParms = mx509.CertParameters{
	O:  "MongoDB",
	OU: "Server",
	CN: "Repro",
}

var clientCAParms = mx509.CertParameters{
	O:  "MongoDB",
	OU: "Client",
	CN: "Repro",
}

func options() error {
	var (
		host = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	)
	flag.Parse()
	var DNSNames = make([]string, 0)
	var IPAddresses = make([]net.IP, 0)
	if len(*host) == 0 {
		DNSNames = append(DNSNames, defaultHost)
	} else {
		hosts := strings.Split(*host, ",")
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				IPAddresses = append(IPAddresses, ip)
			} else {
				DNSNames = append(DNSNames, h)
			}
		}
	}
	serverCAParms.DNSNames = DNSNames
	serverCAParms.IPAddresses = IPAddresses
	return nil
}
