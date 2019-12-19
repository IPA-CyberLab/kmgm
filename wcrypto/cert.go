package wcrypto

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"
)

func VerifyCACert(cert *x509.Certificate, t time.Time) error {
	certpool := x509.NewCertPool()
	certpool.AddCert(cert)

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       certpool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: t,
	}); err != nil {
		return err
	}

	// FIXME[P1]: check BasicConstraints
	// FIXME[P1]: check KeyUsage
	// FIXME[P3]: check pathlen?

	return nil
}

func VerifyServerCert(cert *x509.Certificate, cacert *x509.Certificate, t time.Time) error {
	certpool := x509.NewCertPool()
	certpool.AddCert(cacert)

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       certpool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: t,
	}); err != nil {
		return err
	}

	// FIXME[P1]: check BasicConstraints
	// FIXME[P1]: check KeyUsage
	// FIXME[P3]: check pathlen?

	return nil
}

func VerifyCACertAndKey(priv crypto.PrivateKey, cert *x509.Certificate, t time.Time) error {
	if err := VerifyCACert(cert, t); err != nil {
		return err
	}

	if privv, ok := priv.(interface {
		Validate() error
	}); ok {
		if err := privv.Validate(); err != nil {
			return fmt.Errorf("private key: %w", err)
		}
	}

	priv2pub, err := ExtractPublicKey(priv)
	if err != nil {
		return err
	}

	if err := VerifyPublicKeyMatch(cert.PublicKey, priv2pub); err != nil {
		return fmt.Errorf("The given private key is not for the given CA cert: %w", err)
	}

	return nil
}
