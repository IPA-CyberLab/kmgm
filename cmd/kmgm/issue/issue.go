package issue

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"

	action "github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/frontend/validate"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/structflags"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var ErrCertKeyPathConflict = errors.New("Specified path conflicts with private key output path.")

func PrepareKeyTypePath(env *action.Environment, ktype *wcrypto.KeyType, privPath *string) error {
	slog := env.Logger.Sugar()

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	if *privPath == "" {
		*privPath = filepath.Join(cwd, "key.pem")
		items := []frontend.ConfigItem{
			frontend.ConfigItem{
				Label:    "Private key file",
				Validate: validate.File,
				Value:    privPath,
			},
		}
		if err := env.Frontend.Configure(items); err != nil {
			return err
		}
	}

	_, err = os.Stat(*privPath)
	if err == nil {
		slog.Infof("Found an existing key file %q", privPath)

		priv, err := storage.ReadPrivateKeyFile(*privPath)
		if err != nil {
			return err
		}

		pub, err := wcrypto.ExtractPublicKey(priv)
		if err != nil {
			return err
		}

		extractType, err := wcrypto.KeyTypeOfPub(pub)
		if err != nil {
			return err
		}
		slog.Infof("Successfully read private key of type %v", extractType)

		if *ktype != wcrypto.KeyAny && *ktype != extractType {
			return &UnexpectedKeyTypeErr{Expected: *ktype, Actual: extractType}
		}
		*ktype = extractType
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("os.Stat(%q): %w", *privPath, err)
	}

	if err := validate.MkdirAndCheckWritable(*privPath); err != nil {
		return err
	}

	return nil
}

func EnsurePrivateKey(env *action.Environment, ktype wcrypto.KeyType, privPath string) (crypto.PrivateKey, error) {
	slog := env.Logger.Sugar()

	_, err := os.Stat(privPath)
	if err == nil {
		slog.Infof("Found an existing key file %q", privPath)

		priv, err := storage.ReadPrivateKeyFile(privPath)
		if err != nil {
			return nil, err
		}

		pub, err := wcrypto.ExtractPublicKey(priv)
		if err != nil {
			return nil, err
		}

		extractType, err := wcrypto.KeyTypeOfPub(pub)
		if err != nil {
			return nil, err
		}
		slog.Infof("Successfully read private key of type %v", extractType)

		if ktype != wcrypto.KeyAny && ktype != extractType {
			return nil, &UnexpectedKeyTypeErr{Expected: ktype, Actual: extractType}
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("os.Stat(%q): %w", privPath, err)
	}

	priv, err := wcrypto.GenerateKey(env.Randr, ktype, "", env.Logger)
	if err != nil {
		return nil, err
	}
	if err := storage.WritePrivateKeyFile(privPath, priv); err != nil {
		return nil, err
	}

	return priv, nil
}

func PromptCertPath(env *action.Environment, privPath, certPath string) (string, error) {
	if certPath == "" {
		privDir := filepath.Dir(privPath)
		certPath = filepath.Join(privDir, "cert.pem")
		items := []frontend.ConfigItem{
			frontend.ConfigItem{
				Label: "Certificate pem file",
				Validate: func(s string) error {
					if s == privPath {
						return ErrCertKeyPathConflict
					}
					if err := validate.File(s); err != nil {
						return err
					}

					return nil
				},
				Value: &certPath,
			},
		}
		if err := env.Frontend.Configure(items); err != nil {
			return "", err
		}
	}

	_, err := os.Stat(certPath)
	if err == nil {
		// File already exists.

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			return "", err
		}
		cfg, err := issue.ConfigFromCert(cert)
		if err != nil {
			return "", err
		}
		env.Logger.Sugar().Infof("FIXME[P1] %+v", cfg)
		// FIXME[P1]: extract issuecfg

		return certPath, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("os.Stat(%q): %w", privPath, err)
	}

	if err := validate.MkdirAndCheckWritable(certPath); err != nil {
		return "", err
	}

	return certPath, nil
}

// FIXME[P2]: Help msg for keyType
// FIXME[P2]: Should escape
const ConfigTemplateText = `
---
# kmgm pki new cert config
{{- with .Issue }}
issue:
{{ template "subject" .Subject }}

  # The subjectAltNames specifies hostnames or ipaddrs which the cert is issued
  # against.
  subjectAltNames:
  {{- range .Names.DNSNames }}
    - {{ . }}
  {{- end -}}
  {{- range .Names.IPAddrs }}
    - {{ printf "%v" . }}
  {{- end }}

  # validity specifies the lifetime the cert is valid for.
  validity: {{ printf "%v" .Validity }}
  # validity: 30d # valid for 30 days from now.
  # validity: 2y # valid for 2 years from now.
  # validity: 20220530 # valid until yyyyMMdd.

  keyType: {{ .KeyType }}

  # keyUsage specifies the purpose of the key signed.
  keyUsage:
    # Default. The cert can be used for both TLS client and server.
    {{ CommentOutIfFalse (eq .KeyUsage.Preset "tlsClientServer") -}}
    preset: tlsClientServer

    # The cert valid for TLS server only, and cannot be used for client auth.
    {{ CommentOutIfFalse (eq .KeyUsage.Preset "tlsServer") -}}
    preset: tlsServer

    # The cert valid for TLS client auth only, and cannot be used for server
    # auth.
    {{ CommentOutIfFalse (eq .KeyUsage.Preset "tlsClient") -}}
    preset: tlsClient

    # For advanced users only.
    keyUsage:
    {{ CommentOutIfFalse (and (eq .KeyUsage.Preset "custom") (TestKeyUsageBit "keyEncipherment" .KeyUsage.KeyUsage)) -}}
    - keyEncipherment
    {{ CommentOutIfFalse (and (eq .KeyUsage.Preset "custom") (TestKeyUsageBit "digitalSignature" .KeyUsage.KeyUsage)) -}}
    - digitalSignature
    extKeyUsage:
    {{ CommentOutIfFalse (and (eq .KeyUsage.Preset "custom") (HasExtKeyUsage "any" .KeyUsage.ExtKeyUsages)) -}}
    - any
    {{ CommentOutIfFalse (and (eq .KeyUsage.Preset "custom") (HasExtKeyUsage "clientAuth" .KeyUsage.ExtKeyUsages)) -}}
    - clientAuth
    {{ CommentOutIfFalse (and (eq .KeyUsage.Preset "custom") (HasExtKeyUsage "serverAuth" .KeyUsage.ExtKeyUsages)) -}}
    - serverAuth
{{ end -}}
`

type Config struct {
	PrivateKeyPath string `yaml:"privateKeyPath" flags:"priv,private key input/output path,,path"`
	CertPath       string `yaml:"certPath" flags:"cert,cert input/output path,,path"`

	Issue *issue.Config `yaml:"issue" flags:""`

	// This is here to avoid UnmarshalStrict throw error when noDefault was specified for ShouldLoadDefaults().
	XXX_NoDefault bool `yaml:"noDefault"`
}

type UnexpectedKeyTypeErr struct {
	Expected wcrypto.KeyType
	Actual   wcrypto.KeyType
}

func (e *UnexpectedKeyTypeErr) Error() string {
	return fmt.Sprintf("Expected key type of %s but specified key %s", e.Expected, e.Actual)
}

func (*UnexpectedKeyTypeErr) Is(target error) bool {
	_, ok := target.(*UnexpectedKeyTypeErr)
	return ok
}

func VerifyKeyType(path string, expected wcrypto.KeyType) error {
	if expected == wcrypto.KeyAny {
		return nil
	}

	priv, err := storage.ReadPrivateKeyFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// We are good here, since there is no preexisting key file to enforce the key type.
		return nil
	} else if err != nil {
		return err
	}

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		return err
	}
	ktype, err := wcrypto.KeyTypeOfPub(pub)
	if err != nil {
		return err
	}
	if ktype != expected {
		return fmt.Errorf("Existing key %q: %w", path, &UnexpectedKeyTypeErr{Expected: expected, Actual: ktype})
	}
	return nil
}

func (c *Config) Verify() error {
	// FIXME[P2]: Check CertPath here as well? (currently checked in PromptCertPath)

	if err := c.Issue.Verify(time.Now()); err != nil {
		return err
	}
	if err := VerifyKeyType(c.PrivateKeyPath, c.Issue.KeyType); err != nil {
		return err
	}

	return nil
}

var Command = &cli.Command{
	Name:  "issue",
	Usage: "Issue a new certificate or renew an existing certificate. Generates private key if needed.",
	Flags: append(structflags.MustPopulateFlagsFromStruct(Config{}),
		&cli.BoolFlag{
			Name:  "dump-template",
			Usage: "dump configuration template yaml without making actual changes",
		},
	),
	Action: func(c *cli.Context) error {
		env := action.GlobalEnvironment
		slog := env.Logger.Sugar()

		profile, err := env.Profile()
		if err != nil {
			return err
		}

		cfg := &Config{}
		if c.Bool("dump-template") || env.Frontend.ShouldLoadDefaults() {
			slog.Debugf("Constructing default config.")

			var caSubject *dname.Config
			// Inherit CA subject iff CA is setup.
			if st := profile.Status(); st == nil {
				var err error
				caSubject, err = profile.ReadCASubject()
				if err != nil {
					return err
				}
			}

			issuecfg, err := issue.DefaultConfig(caSubject)
			// issue.DefaultConfig errors are ignorable.
			if err != nil && !c.Bool("dump-template") {
				slog.Debugf("Errors encountered while constructing default config: %v", err)
			}
			cfg.Issue = issuecfg
		} else {
			slog.Debugf("Config is from scratch.")
			cfg.Issue = issue.EmptyConfig()
		}

		if c.Bool("dump-template") {
			if err := frontend.DumpTemplate(ConfigTemplateText, cfg); err != nil {
				return err
			}
			return nil
		}

		if err := setup.EnsureCA(env, nil, profile, false); err != nil {
			return err
		}

		err = PrepareKeyTypePath(env, &cfg.Issue.KeyType, &cfg.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("Failed to acquire private key: %w", err)
		}

		cfg.CertPath, err = PromptCertPath(env, cfg.PrivateKeyPath, cfg.CertPath)
		if err != nil {
			return fmt.Errorf("Failed to acquire certificate file path: %w", err)
		}

		if err := frontend.EditStructWithVerifier(
			env.Frontend, ConfigTemplateText, cfg, frontend.CallVerifyMethod); err != nil {
			return err
		}
		if err := structflags.PopulateStructFromCliContext(cfg, c); err != nil {
			return err
		}

		priv, err := EnsurePrivateKey(env, cfg.Issue.KeyType, cfg.PrivateKeyPath)
		if err != nil {
			return err
		}

		pub, err := wcrypto.ExtractPublicKey(priv)
		if err != nil {
			return err
		}

		certDer, err := issue.Run(env, pub, cfg.Issue)
		if err != nil {
			return err
		}

		if err := storage.WriteCertificateDerFile(cfg.CertPath, certDer); err != nil {
			return err
		}

		return nil
	},
}
