package setup

import (
	"fmt"

	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
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

func (cfg *Config) Verify() error {
	if err := cfg.Subject.Verify(); err != nil {
		return fmt.Errorf("Subject.%w", err)
	}

	return nil
}
