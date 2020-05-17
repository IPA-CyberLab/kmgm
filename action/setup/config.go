package setup

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var (
	ErrSubjectEmpty = errors.New("CA Subject must not be empty.")
)

type Config struct {
	Subject  *dname.Config         `yaml:"subject" flags:""`
	Validity period.ValidityPeriod `yaml:"validity" flags:"validity,time duration/timestamp where the cert is valid to (examples: 30d&comma; 1y&comma; 20220530)"`
	KeyType  wcrypto.KeyType       `yaml:"keyType" flags:"key-type,private key type (rsa&comma; ecdsa),t"`

	NameConstraints NameConstraints `yaml:"nameConstraints"`
}

func DefaultConfig(baseSubject *dname.Config) *Config {
	return &Config{
		Subject:  dname.DefaultConfig(" CA", baseSubject),
		KeyType:  wcrypto.KeyRSA4096,
		Validity: period.FarFuture,
	}
}

func EmptyConfig() *Config {
	return &Config{
		Subject: &dname.Config{},
	}
}

func ConfigFromCert(cert *x509.Certificate) (*Config, error) {
	kt, err := wcrypto.KeyTypeOfPub(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Config{
		Subject:  dname.FromPkixName(cert.Subject),
		KeyType:  kt,
		Validity: period.ValidityPeriod{NotAfter: cert.NotAfter},
	}, nil
}

func (a *Config) CompatibleWith(b *Config) error {
	if err := a.Subject.CompatibleWith(b.Subject); err != nil {
		return err
	}
	if a.KeyType != b.KeyType {
		return fmt.Errorf("KeyType mismatch: %v != %v", a.KeyType, b.KeyType)
	}
	return nil
}

const expireThreshold = 30 * time.Second

var ErrValidityPeriodExpired = errors.New("Declining to setup CA which expires within 30 seconds.")

func (cfg *Config) Verify(now time.Time) error {
	if err := cfg.Subject.Verify(); err != nil {
		return fmt.Errorf("Subject.%w", err)
	}
	if cfg.Subject.IsEmpty() {
		return ErrSubjectEmpty
	}
	if cfg.Validity.GetNotAfter(now).Before(now.Add(expireThreshold)) {
		return ErrValidityPeriodExpired
	}

	return nil
}
