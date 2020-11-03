package pemparser

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ForeachPemBlock(pemText []byte, f func(*pem.Block) error) error {
	for len(pemText) > 0 {
		var block *pem.Block
		block, pemText = pem.Decode(pemText)
		if block == nil {
			break
		}

		if err := f(block); err != nil {
			return err
		}
	}

	return nil
}

var ErrMultipleCertificateRequestBlocks = errors.New("Found more than one CERTIFICATE REQUEST block")

func ParseCertificateRequest(pemText []byte) (req *x509.CertificateRequest, err error) {
	err = ForeachPemBlock(pemText, func(block *pem.Block) error {
		if block.Type != CertificateRequestPemType {
			return nil
		}

		if req != nil {
			err = ErrMultipleCertificateRequestBlocks
			return err
		}

		req, err = x509.ParseCertificateRequest(block.Bytes)
		return err
	})
	if err == nil && req == nil {
		err = fmt.Errorf("Target pem block %q not found.", CertificateRequestPemType)
		return
	}
	return
}

func ParseCertificates(pemText []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	if err := ForeachPemBlock(pemText, func(block *pem.Block) error {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		certs = append(certs, cert)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("No certificate was found.")
	}

	return certs, nil
}

func ParseSinglePrivateKeyBlock(block *pem.Block) (crypto.PrivateKey, error) {
	der := block.Bytes
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("Failed to parse private key.")
}

func ParsePrivateKey(pemText []byte) (crypto.PrivateKey, error) {
	var priv crypto.PrivateKey

	if err := ForeachPemBlock(pemText, func(block *pem.Block) error {
		newpriv, err := ParseSinglePrivateKeyBlock(block)
		if err == nil {
			if priv != nil {
				return errors.New("More than one private key found in given pemText.")
			}
			priv = newpriv
		}

		return nil
	}); err != nil {
		return nil, err
	}
	if priv == nil {
		return nil, errors.New("Failed to parse private key.")
	}

	return priv, nil
}
