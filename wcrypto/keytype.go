package wcrypto

import "fmt"

type KeyType int

const (
	KeyAny KeyType = iota
	KeyRSA4096
	KeySECP256R1
)

var ServerKeyType = KeySECP256R1

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

// FIXME[P1]: KeyType yaml.Unmarshaler
