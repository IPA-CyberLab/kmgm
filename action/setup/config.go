package setup

import (
	"errors"
	"fmt"

	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var (
	ErrSubjectEmpty = errors.New("CA Subject must not be empty.")
)

type Config struct {
	Subject *dname.Config   `yaml:"subject" flags:""`
	KeyType wcrypto.KeyType `yaml:"keyType" flags:"key-type,private key type (rsa&comma; rcdsa),t"`
}

func DefaultConfig() (*Config, error) {
	subject, err := dname.DefaultConfig(" CA", nil)

	cfg := &Config{
		Subject: subject,
		KeyType: wcrypto.KeyRSA4096,
	}
	return cfg, err
}

func EmptyConfig() *Config {
	return &Config{
		Subject: &dname.Config{},
	}
}

func (cfg *Config) Verify() error {
	if err := cfg.Subject.Verify(); err != nil {
		return fmt.Errorf("Subject.%w", err)
	}
	// FIXME[P2]: Test me
	if cfg.Subject.IsEmpty() {
		return ErrSubjectEmpty
	}

	return nil
}
