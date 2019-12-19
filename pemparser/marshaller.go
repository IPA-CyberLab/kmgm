package pemparser

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
)

func MarshalPrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	switch impl := priv.(type) {
	case (*rsa.PrivateKey):
		bs := pem.EncodeToMemory(&pem.Block{
			Type:  RSAPrivateKeyPemType,
			Bytes: x509.MarshalPKCS1PrivateKey(impl),
		})
		return bs, nil
	case (*ecdsa.PrivateKey):
		kbs, err := x509.MarshalECPrivateKey(impl)
		if err != nil {
			return nil, err
		}
		bs := pem.EncodeToMemory(&pem.Block{
			Type:  ECPrivateKeyPemType,
			Bytes: kbs,
		})
		return bs, nil

	default:
		return nil, fmt.Errorf("Couldn't marshal unknown private key type: %v", reflect.TypeOf(priv))
	}
}

func MarshalCertificateDer(certDer []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  CertificatePemType,
		Bytes: certDer,
	})
}
