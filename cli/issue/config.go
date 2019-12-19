package issue

import (
	"crypto/x509"
	"fmt"

	"github.com/IPA-CyberLab/kmgm/cli"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

type Config struct {
	Subject  *dname.Config     `yaml:"subject" flags:""`
	Names    san.Names         `yaml:"subjectAltNames" flags:"subject-alt-name,set cert subjectAltNames,san"`
	KeyUsage keyusage.KeyUsage `yaml:"keyUsage" flags:"key-usage,what the key/cert is used for (tlsServer&comma; tlsClient&comma; tlsClientServer),ku"`
	Validity ValidityPeriod    `yaml:"validity" flags:"validity,time duration/timestamp where the cert is valid to (examples: 30d&comma; 1y&comma; 20220530)"`
	KeyType  wcrypto.KeyType   `yaml:"keyType" flags:"key-type,private key type (rsa&comma; rcdsa),t"`

	// Don't create issuedb entry.
	NoIssueDBEntry bool
}

func DefaultConfig(env *cli.Environment) (*Config, error) {
	profile, err := env.Profile()
	if err != nil {
		return nil, err
	}

	caSubject, err := profile.ReadCASubject()
	if err != nil {
		return nil, err
	}

	subject, err := dname.DefaultConfig("", caSubject)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Subject:  subject,
		Names:    san.ForThisHost(""),
		KeyUsage: keyusage.KeyUsageTLSClientServer.Clone(),
		Validity: ValidityPeriod{Days: 820},
		KeyType:  wcrypto.KeyRSA4096,
	}
	return cfg, nil
}

func ConfigFromCert(cert *x509.Certificate) *Config {
	return &Config{
		Subject:  dname.FromPkixName(cert.Subject),
		Names:    san.FromCertificate(cert),
		KeyUsage: keyusage.FromCertificate(cert),
		// FIXME[P1]: validity
		// FIXME[P1]: keytype
	}
}

func (cfg *Config) Verify() error {
	if err := cfg.Subject.Verify(); err != nil {
		return fmt.Errorf("Subject.%w", err)
	}
	if err := cfg.Names.Verify(); err != nil {
		return fmt.Errorf("Names.%w", err)
	}
	// FIXME[P1]: Implement keyusage verify
	// if err := cfg.KeyUsage.Verify(); err != nil {
	// 	return fmt.Errorf("KeyUsage.%w", err)
	// }

	return nil
}
