package wcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"go.uber.org/zap"
)

var ErrKeyAnyForGenerateKey = errors.New("KeyAny is not a valid keytype for wcrypto.GenerateKey") //nolint

func GenerateKey(randr io.Reader, ktype KeyType, usage string, logger *zap.Logger) (crypto.PrivateKey, error) {
	slog := logger.Sugar()
	start := time.Now()

	slog.Infow("Generating key...", "usage", usage, "type", ktype)
	defer func() {
		slog.Infow("Generating key... Done.", "usage", usage, "type", ktype, "took", time.Since(start))
	}()

	switch ktype {
	case KeyRSA4096:
		priv, err := rsa.GenerateKey(randr, 4096)
		if err != nil {
			return nil, fmt.Errorf("rsa.GenerateKey: %w", err)
		}
		return priv, nil

	case KeySECP256R1:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), randr)
		if err != nil {
			return nil, fmt.Errorf("ecdsa.GenerateKey: %w", err)
		}
		return priv, nil

	case KeyAny:
		return nil, ErrKeyAnyForGenerateKey

	default:
		return nil, fmt.Errorf("unknown key type: %v", ktype)
	}
}

func ExtractPublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	privp, ok := priv.(interface {
		Public() crypto.PublicKey
	})
	if !ok {
		return nil, errors.New("could not extract public key from private key")
	}
	pub := privp.Public()
	return pub, nil
}

func errTypeMismatch(a, b interface{}) error {
	return fmt.Errorf("Type mismatch: %v and %v", reflect.TypeOf(a), reflect.TypeOf(b))
}

var ErrPublicKeyMismatch = errors.New("public keys do not match")

func VerifyPublicKeyMatch(a, b crypto.PublicKey) error {
	switch at := a.(type) {
	case *rsa.PublicKey:
		bt, ok := b.(*rsa.PublicKey)
		if !ok {
			return errTypeMismatch(a, b)
		}
		if at.N.Cmp(bt.N) != 0 || at.E != bt.E {
			return ErrPublicKeyMismatch
		}
	case *ecdsa.PublicKey:
		bt, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return errTypeMismatch(a, b)
		}
		if at.X.Cmp(bt.X) != 0 || at.Y.Cmp(bt.Y) != 0 {
			return ErrPublicKeyMismatch
		}
	default:
		return fmt.Errorf("Unknown public key type: %v", reflect.TypeOf(a))
	}
	return nil
}

// PubKeyPinString extracts the SHA256 hash for use of curl`s --pinnedpubkey commandline option.
func PubKeyPinString(pub crypto.PublicKey) (string, error) {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(pkix)
	str := base64.StdEncoding.EncodeToString(hash[:])
	return str, nil
}

func SubjectKeyIdFromPubkey(pub crypto.PublicKey) ([]byte, error) {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var target struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(pkix, &target); err != nil {
		return nil, err
	}

	ski := sha1.Sum(target.SubjectPublicKey.Bytes)
	return ski[:], nil
}
