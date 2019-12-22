package wcrypto

import "fmt"

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
