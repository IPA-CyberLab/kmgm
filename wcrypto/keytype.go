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

var DefaultKeyType = KeyRSA4096
var ServerKeyType = KeySECP256R1

func (kt KeyType) String() string {
	switch kt {
	case KeyAny:
		return "any"
	case KeyRSA4096:
		return "rsa"
	case KeySECP256R1:
		return "ecdsa"
	default:
		return fmt.Sprintf("unknown_keytype%d", int(kt))
	}
}

func KeyTypeFromString(s string) (KeyType, error) {
	switch s {
	case "any":
		return KeyAny, nil
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

type UnexpectedKeyTypeErr struct {
	Expected KeyType
	Actual   KeyType
}

func (e UnexpectedKeyTypeErr) Error() string {
	return fmt.Sprintf("Expected key type of %s but specified key %s", e.Expected, e.Actual)
}

func (UnexpectedKeyTypeErr) Is(target error) bool {
	_, ok := target.(UnexpectedKeyTypeErr)
	return ok
}

func (expected KeyType) CompatibleWith(actual KeyType) error {
	if expected == KeyAny {
		return nil
	}
	if expected != actual {
		return UnexpectedKeyTypeErr{Expected: expected, Actual: actual}
	}
	return nil
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
