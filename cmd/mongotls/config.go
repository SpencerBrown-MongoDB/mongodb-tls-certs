package main

import "github.com/SpencerBrown/mongodb-tls-certs/mx509"

const hostname = "mongodb-local.computer"

const tlsDirectory = "tls"

const (
	rootCAFilename         = "root-ca"
	signingCAFilename      = "signing-ca"
	OCSPSigningFilename    = "ocsp"
	serverFilename         = "server"
	clientFilename         = "client"
	certificateKeyFilename = "key-cert"
	CAFileFilename         = "ca-chain"
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
	O:       "MongoDB",
	OU:      "Server",
	CN:      "Repro",
	Servers: []string{hostname},
}

var clientCAParms = mx509.CertParameters{
	O:  "MongoDB",
	OU: "Client",
	CN: "Repro",
}
