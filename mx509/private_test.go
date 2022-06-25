package mx509

import (
	"reflect"
	"testing"
)

// this alwo tests GetPrivateKey, more or less

func TestCreatePrivateKey(t *testing.T) {
	key, pem, err := CreatePrivateKey(2048)
	if err != nil {
		t.Errorf("error creating private key: %v", err)
	}
	key2, err := GetPrivateKey(pem)
	if err != nil {
		t.Errorf("error decoding PEM private key: %v", err)
	}
	if !reflect.DeepEqual(key, key2) {
		t.Errorf("want: %v, got: %v", key, key2)
	}
}
