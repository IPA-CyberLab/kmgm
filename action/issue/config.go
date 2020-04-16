package issue

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/validityperiod"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

type Config struct {
	Subject  *dname.Config                 `yaml:"subject" flags:""`
	Names    san.Names                     `yaml:"subjectAltNames" flags:"subject-alt-name,set cert subjectAltNames,san"`
	KeyUsage keyusage.KeyUsage             `yaml:"keyUsage" flags:"key-usage,what the key/cert is used for (tlsServer&comma; tlsClient&comma; tlsClientServer),ku"`
	Validity validityperiod.ValidityPeriod `yaml:"validity" flags:"validity,time duration/timestamp where the cert is valid to (examples: 30d&comma; 1y&comma; 20220530)"`
	KeyType  wcrypto.KeyType               `yaml:"keyType" flags:"key-type,private key type (rsa&comma; rcdsa),t"`

	// Don't create issuedb entry.
	NoIssueDBEntry bool
}

func DefaultConfig(baseSubject *dname.Config) (*Config, error) {
	subject, err := dname.DefaultConfig("", baseSubject)
	// dname.DefaultConfig error is ignorable

	cfg := &Config{
		Subject:  subject,
		Names:    san.ForThisHost(""),
		KeyUsage: keyusage.KeyUsageTLSClientServer.Clone(),
		Validity: validityperiod.ValidityPeriod{Days: 820},
		KeyType:  wcrypto.KeyRSA4096,
	}
	return cfg, err
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
		Names:    san.FromCertificate(cert),
		KeyUsage: keyusage.FromCertificate(cert),
		Validity: validityperiod.ValidityPeriod{NotAfter: cert.NotAfter},
		KeyType:  kt,
	}, nil
}

func (a *Config) CompatibleWith(b *Config) error {
	if err := a.Subject.CompatibleWith(b.Subject); err != nil {
		return err
	}
	if err := a.Names.CompatibleWith(b.Names); err != nil {
		return err
	}
	if !a.KeyUsage.Equals(b.KeyUsage) {
		return fmt.Errorf("KeyUsage mismatch")
	}
	if a.KeyType != b.KeyType {
		return fmt.Errorf("KeyType mismatch: %v != %v", a.KeyType, b.KeyType)
	}
	return nil
}

const expireThreshold = 30 * time.Second

var ErrValidityPeriodExpired = errors.New("Declining to issue certificate which expires within 30 seconds.")

func (cfg *Config) Verify(now time.Time) error {
	if err := cfg.Subject.Verify(); err != nil {
		return fmt.Errorf("Subject.%w", err)
	}
	if err := cfg.Names.Verify(); err != nil {
		return fmt.Errorf("Names.%w", err)
	}
	if err := cfg.KeyUsage.Verify(); err != nil {
		return fmt.Errorf("KeyUsage.%w", err)
	}
	if cfg.Validity.GetNotAfter(now).Before(now.Add(expireThreshold)) {
		return ErrValidityPeriodExpired
	}

	return nil
}
