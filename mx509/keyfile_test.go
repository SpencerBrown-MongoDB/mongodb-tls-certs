package mx509

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestCreateKeyFile(t *testing.T) {
	got := CreateKeyFile()
	if len(got) != 44 {
		t.Errorf("invalid length of keyfile, should be 44: '%s'", string(got))
	}
	x := make([]byte, 32)
	_, err := base64.StdEncoding.Decode(x, got)
	if err != nil {
		t.Errorf("invalid base64-encoded keyfile '%s': %v", string(got), err)
	}
}

func Test_base64Encode(t *testing.T) {
	type args struct {
		message []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "test1",
			args: args{
				message: []byte("Hello World"),
			},
			want: []byte("SGVsbG8gV29ybGQ="),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base64Encode(tt.args.message); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("base64Encode() = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}
