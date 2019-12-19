package setup

import (
	"fmt"

	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

type Config struct {
	KeyType wcrypto.KeyType
	Subject *dname.Config `yaml:"subject"`
}

func DefaultConfig() (*Config, error) {
	subject, err := dname.DefaultConfig(" CA", nil)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		KeyType: wcrypto.KeyRSA4096,
		Subject: subject,
	}
	return cfg, nil
}

func (cfg *Config) Verify() error {
	if err := cfg.Subject.Verify(); err != nil {
		return fmt.Errorf("Subject.%w", err)
	}

	return nil
}
