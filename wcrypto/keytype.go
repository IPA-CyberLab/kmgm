package wcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"reflect"
)

type KeyType int

const (
	KeyAny KeyType = iota
	KeyRSA4096
	KeySECP256R1
)

var ServerKeyType = KeySECP256R1

func (kt KeyType) String() string {
	switch kt {
	case KeyRSA4096:
		return "rsa"
	case KeySECP256R1:
		return "ecdsa"
	default:
		return "unknown_keytype"
	}
}

func KeyTypeFromString(s string) (KeyType, error) {
	switch s {
	case "rsa":
		return KeyRSA4096, nil
	case "secp256r1", "ecdsa":
		return KeySECP256R1, nil
	default:
		return KeyRSA4096, fmt.Errorf("Unknown key type %q.", s)
	}
}

func KeyTypeOfPub(pub crypto.PublicKey) (KeyType, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		bitlen := p.N.BitLen()
		switch bitlen {
		case 4096:
			return KeyRSA4096, nil
		default:
			return KeyAny, fmt.Errorf("rsa.PublicKey with unsupported key size of %d", bitlen)
		}

	case *ecdsa.PublicKey:
		curven := p.Curve.Params().Name
		switch curven {
		case "P-256":
			return KeySECP256R1, nil
		default:
			return KeyAny, fmt.Errorf("ecdsa.PublicKey with unsupported curve %q", curven)
		}

	default:
		return KeyAny, fmt.Errorf("Unknown public key type: %v", reflect.TypeOf(pub))
	}
}

func (p *KeyType) UnmarshalFlag(s string) error {
	kt, err := KeyTypeFromString(s)
	if err != nil {
		return err
	}

	*p = kt
	return nil
}

func (p *KeyType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	kt, err := KeyTypeFromString(s)
	if err != nil {
		return err
	}

	*p = kt
	return nil
}
