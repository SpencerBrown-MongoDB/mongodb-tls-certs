package mx509

import (
	"encoding/base64"
	"math/rand"
)

// CreateKeyFile creates a random 32 bytes and returns it as a byte64 encoded string.
func CreateKeyFile() []byte {
	r32 := make([]byte, 32, 32)
	_, _ = rand.Read(r32)
	return base64Encode(r32)
}

// base64Encode encodes a byte slide to a base64 equivalent as a byte slice
// copied from https://gist.github.com/Xeoncross/e83313ac7157c659416676a6044fcd1e
func base64Encode(message []byte) []byte {
	b := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(b, message)
	return b
}
