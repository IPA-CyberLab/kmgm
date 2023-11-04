package issue

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"go.uber.org/multierr"

	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

type Config struct {
	Subject  *dname.Config         `yaml:"subject" flags:""`
	Names    san.Names             `yaml:"subjectAltNames" flags:"subject-alt-name,set cert subjectAltNames,san"`
	KeyUsage keyusage.KeyUsage     `yaml:"keyUsage" flags:"key-usage,what the key/cert is used for (tlsServer&comma; tlsClient&comma; tlsClientServer),ku"`
	Validity period.ValidityPeriod `yaml:"validity" flags:"validity,time duration/timestamp where the cert is valid to (examples: 30d&comma; 1y&comma; 20220530)"`
	KeyType  wcrypto.KeyType       `yaml:"keyType" flags:"key-type,private key type (rsa&comma; ecdsa),t"`

	// Don't create issuedb entry.
	NoIssueDBEntry bool
}

func DefaultConfig(baseSubject *dname.Config) *Config {
	var ns san.Names

	override := os.Getenv("KMGM_DEFAULT_NAMES")
	if override != "" {
		var err error
		ns, err = san.Parse(override)
		if err != nil {
			log.Panicf("Failed to parse KMGM_DEFAULT_NAMES %q: %v", override, err)
		}
	} else {
		ns = san.ForThisHost()
	}

	return &Config{
		Subject:  dname.DefaultConfig("", baseSubject),
		Names:    ns,
		KeyUsage: keyusage.KeyUsageTLSClientServer.Clone(),
		Validity: period.ValidityPeriod{Days: 820},
		KeyType:  wcrypto.KeyAny,
	}
}

func EmptyConfig() *Config {
	return &Config{
		Subject: &dname.Config{},
	}
}

func (o *Config) Clone() *Config {
	return &Config{
		Subject:        o.Subject.Clone(),
		Names:          o.Names.Clone(),
		KeyUsage:       o.KeyUsage,
		Validity:       o.Validity,
		KeyType:        o.KeyType,
		NoIssueDBEntry: o.NoIssueDBEntry,
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
		Validity: period.ValidityPeriod{NotAfter: cert.NotAfter},
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
		return fmt.Errorf("KeyUsage mismatch: %v != %v", a.KeyUsage, b.KeyUsage)
	}
	if err := a.KeyType.CompatibleWith(b.KeyType); err != nil {
		return err
	}
	return nil
}

const expireThreshold = 30 * time.Second

var ErrValidityPeriodExpired = errors.New("Declining to issue certificate which expires within 30 seconds.")

func (cfg *Config) Verify(now time.Time) error {
	var merr error
	if err := cfg.Subject.Verify(); err != nil {
		merr = fmt.Errorf("Subject.%w", err)
	}
	if err := cfg.Names.Verify(); err != nil {
		merr = multierr.Append(merr, fmt.Errorf("Names.%w", err))
	}
	if err := cfg.KeyUsage.Verify(); err != nil {
		merr = multierr.Append(merr, fmt.Errorf("KeyUsage.%w", err))
	}
	if cfg.Validity.GetNotAfter(now).Before(now.Add(expireThreshold)) {
		merr = multierr.Append(merr, ErrValidityPeriodExpired)
	}

	return merr
}
