package setup

import (
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
	Subject  *dname.Config                 `yaml:"subject" flags:""`
	Validity period.ValidityPeriod `yaml:"validity" flags:"validity,time duration/timestamp where the cert is valid to (examples: 30d&comma; 1y&comma; 20220530)"`
	KeyType  wcrypto.KeyType               `yaml:"keyType" flags:"key-type,private key type (rsa&comma; ecdsa),t"`
}

func DefaultConfig() (*Config, error) {
	subject, err := dname.DefaultConfig(" CA", nil)

	cfg := &Config{
		Subject:  subject,
		KeyType:  wcrypto.KeyRSA4096,
		Validity: period.FarFuture,
	}
	return cfg, err
}

func EmptyConfig() *Config {
	return &Config{
		Subject: &dname.Config{},
	}
}

const expireThreshold = 30 * time.Second

var ErrValidityPeriodExpired = errors.New("Declining to setup CA which expires within 30 seconds.")

func (cfg *Config) Verify(now time.Time) error {
	if err := cfg.Subject.Verify(); err != nil {
		return fmt.Errorf("Subject.%w", err)
	}
	// FIXME[P2]: Test me
	if cfg.Subject.IsEmpty() {
		return ErrSubjectEmpty
	}
	if cfg.Validity.GetNotAfter(now).Before(now.Add(expireThreshold)) {
		return ErrValidityPeriodExpired
	}

	return nil
}
