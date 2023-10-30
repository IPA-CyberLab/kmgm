package issue

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/app/appflags"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/frontend/validate"
	"github.com/IPA-CyberLab/kmgm/ipapi"
	"github.com/IPA-CyberLab/kmgm/period"
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
		items := []frontend.ConfigItem{{
			Label:    "Private key file",
			Validate: validate.File,
			Value:    privPath,
		}}
		if err := env.Frontend.Configure(items); err != nil {
			return err
		}
	}

	_, err = os.Stat(*privPath)
	if err == nil {
		slog.Infof("Found an existing key file: %s", *privPath)

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

		if err := ktype.CompatibleWith(extractType); err != nil {
			return err
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

		if err := ktype.CompatibleWith(extractType); err != nil {
			return nil, err
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("os.Stat(%q): %w", privPath, err)
	}

	if ktype == wcrypto.KeyAny {
		ktype = wcrypto.DefaultKeyType
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
		items := []frontend.ConfigItem{{
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
		}}
		if err := env.Frontend.Configure(items); err != nil {
			return "", err
		}
	}

	_, err := os.Stat(certPath)
	if err == nil {
		// File already exists.

		if _, err := storage.ReadCertificateFile(certPath); err != nil {
			return "", err
		}

		return certPath, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("os.Stat(%q): %w", certPath, err)
	}

	if err := validate.MkdirAndCheckWritable(certPath); err != nil {
		return "", err
	}

	return certPath, nil
}

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
    - {{ . | YamlEscapeString }}
  {{- end -}}
  {{- range .Names.IPAddrs }}
    - {{ printf "%v" . }}
  {{- end }}

  # validity specifies the lifetime the cert is valid for.
  validity: {{ printf "%v" .Validity }}
  # validity: 30d # valid for 30 days from now.
  # validity: 2y # valid for 2 years from now.
  # validity: 20220530 # valid until yyyyMMdd.

  # The type of private/public key pair.
  keyType: {{ .KeyType }}
  # keyType: any # Accept any key type, or create RSA key pair if not exists.
  # keyType: rsa
  # keyType: ecdsa

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
{{ end }}

# Private key file path:
#   If the file exists, kmgm reads it.
#   If the file does not exist, kmgm generates a new one.
privateKeyPath: {{ .PrivateKeyPath | YamlEscapeString }}

# Certificate file path:
#   If the file exists, kmgm renews the certificate.
#   If the file does not exist, kmgm issues a fresh one.
certPath: {{ .CertPath | YamlEscapeString }}

# Renew certificate only if it expires within the specified threshold.
renewBefore: {{ .RenewBefore }}
# renewBefore: immediately # renew regardless of the expiration date.
# renewBefore: 7d # renew only if the certificate is set to expire within 7 days.
`

type Config struct {
	PrivateKeyPath string `yaml:"privateKeyPath" flags:"priv,private key input/output path,,path"`
	CertPath       string `yaml:"certPath" flags:"cert,cert input/output path,,path"`

	Issue *issue.Config `yaml:"issue" flags:""`

	RenewBefore period.Days `yaml:"renewBefore" flags:"renew-before,when specified&comma; renew only if the certificate expires within specified threshold,,duration"`

	// This is here to avoid yaml.v3 Decoder with KnownFields(true) throwing error for valid AppFlags fields
	XXX_AppFlags appflags.AppFlags `yaml:",inline"`
}

func VerifyKeyType(path string, expected wcrypto.KeyType) (crypto.PublicKey, error) {
	priv, err := storage.ReadPrivateKeyFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// We are good here, since there is no preexisting key file to enforce the key type.
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		return nil, err
	}

	ktype, err := wcrypto.KeyTypeOfPub(pub)
	if err != nil {
		return nil, err
	}

	if err := expected.CompatibleWith(ktype); err != nil {
		return nil, fmt.Errorf("Existing key %q: %w", path, err)
	}

	return pub, nil
}

type IncompatibleCertErr struct {
	Wrap error
}

func (e IncompatibleCertErr) Error() string {
	return fmt.Sprintf("Certificate renewal requested, but the cert was issued with a different config. Please specify a matching config or different certPath: %v", e.Wrap)
}

func (IncompatibleCertErr) Is(target error) bool {
	_, ok := target.(IncompatibleCertErr)
	return ok
}

func (e IncompatibleCertErr) Unwrap() error {
	return e.Wrap
}

type CertStillValidErr struct {
	ValidLeft   time.Duration
	RenewBefore period.Days
}

func (e CertStillValidErr) Error() string {
	days := (e.ValidLeft / (24 * time.Hour))
	return fmt.Sprintf("Existing cert valid for %dd (%v), which is more than renewBefore %v (%v)",
		days, e.ValidLeft, e.RenewBefore, e.RenewBefore.ToDuration())
}

func (CertStillValidErr) Is(target error) bool {
	_, ok := target.(CertStillValidErr)
	return ok
}

func (CertStillValidErr) ExitCode() int {
	return 10
}

func (c *Config) verifyExistingCert(env *action.Environment, pub crypto.PublicKey) error {
	s := env.Logger.Sugar()

	if _, err := os.Stat(c.CertPath); err == nil {
		// File already exists.

		cert, err := storage.ReadCertificateFile(c.CertPath)
		if err != nil {
			return err
		}
		s.Infof("Successfully read existing cert: %s", c.CertPath)

		certCfg, err := issue.ConfigFromCert(cert)
		if err != nil {
			return err
		}

		if err := c.Issue.CompatibleWith(certCfg); err != nil {
			return IncompatibleCertErr{Wrap: err}
		}

		now := env.NowImpl()
		validLeft := cert.NotAfter.Sub(now)
		s.Infof("Existing cert valid until %s.", cert.NotAfter.Format(time.UnixDate))

		if d := c.RenewBefore.ToDuration(); d == 0 {
			s.Infof("Proceeding anyways, since an immediate renewal was specified.")
		} else if validLeft > d {
			return CertStillValidErr{ValidLeft: validLeft, RenewBefore: c.RenewBefore}
		} else {
			s.Infof("Existing cert valid for %s, which is less than renewBefore %v (%v). Proceeding with renewal.", validLeft, c.RenewBefore, d)
		}

		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("os.Stat(%q): %w", c.CertPath, err)
	} else {
		// File does not exist.

		if err := validate.MkdirAndCheckWritable(c.CertPath); err != nil {
			return err
		}
		return nil
	}
}

func (c *Config) Verify(env *action.Environment) error {
	if err := c.Issue.Verify(env.NowImpl()); err != nil {
		return err
	}
	pub, err := VerifyKeyType(c.PrivateKeyPath, c.Issue.KeyType)
	if err != nil {
		return err
	}
	if err := c.verifyExistingCert(env, pub); err != nil {
		return err
	}

	return nil
}

type Strategy interface {
	EnsureCA(ctx context.Context, env *action.Environment) error
	CASubject(ctx context.Context, env *action.Environment) *dname.Config
	Issue(ctx context.Context, env *action.Environment, pub crypto.PublicKey, cfg *issue.Config) ([]byte, error)
}

func ActionImpl(strategy Strategy, c *cli.Context) error {
	af := c.App.Metadata["AppFlags"].(*appflags.AppFlags)

	env := action.GlobalEnvironment
	slog := env.Logger.Sugar()

	var cfg *Config
	if c.Bool("dump-template") || !af.NoDefault {
		slog.Debugf("Constructing default config.")

		baseSubject := strategy.CASubject(c.Context, env)
		if baseSubject == nil {
			geo, err := ipapi.QueryCached(env.Storage.GeoIpCachePath(), env.Logger)
			if err != nil {
				slog.Infof("ipapi.QueryCached: %v", err)
			}
			if geo == nil {
				geo = &ipapi.Result{}
			}
			baseSubject = dname.FromGeoip(geo)
		}

		cfg = &Config{Issue: issue.DefaultConfig(baseSubject)}
	} else {
		slog.Debugf("Config is from scratch.")
		cfg = &Config{Issue: issue.EmptyConfig()}
	}

	if !c.Bool("dump-template") {
		if err := strategy.EnsureCA(c.Context, env); err != nil {
			return err
		}
	}

	if cfgbs, ok := c.App.Metadata["config"]; ok {
		r := bytes.NewBuffer(cfgbs.([]byte))

		d := yaml.NewDecoder(r)
		d.KnownFields(true)

		if err := d.Decode(cfg); err != nil {
			return err
		}
	}
	if err := structflags.PopulateStructFromCliContext(cfg, c); err != nil {
		return err
	}

	if c.Bool("dump-template") {
		if err := frontend.DumpTemplate(ConfigTemplateText, cfg); err != nil {
			return err
		}
		return nil
	}

	if err := PrepareKeyTypePath(env, &cfg.Issue.KeyType, &cfg.PrivateKeyPath); err != nil {
		return fmt.Errorf("Failed to acquire private key: %w", err)
	}

	var err error
	cfg.CertPath, err = PromptCertPath(env, cfg.PrivateKeyPath, cfg.CertPath)
	if err != nil {
		return fmt.Errorf("Failed to acquire certificate file path: %w", err)
	}

	if err := frontend.EditStructWithVerifier(
		env.Frontend, ConfigTemplateText, cfg, func(cfgI interface{}) error {
			cfg := cfgI.(*Config)
			if err := cfg.Verify(env); err != nil {
				return err
			}
			return nil
		}); err != nil {
		return err
	}

	return IssuePrivateKeyAndCertificateFile(c.Context, env, strategy, cfg)
}

func IssuePrivateKeyAndCertificateFile(ctx context.Context, env *action.Environment, strategy Strategy, cfg *Config) error {
	priv, err := EnsurePrivateKey(env, cfg.Issue.KeyType, cfg.PrivateKeyPath)
	if err != nil {
		return err
	}

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		return err
	}

	certDer, err := strategy.Issue(ctx, env, pub, cfg.Issue)
	if err != nil {
		return err
	}

	if err := storage.WriteCertificateDerFile(cfg.CertPath, certDer); err != nil {
		return err
	}

	return nil
}

type Local struct {
	Profile *storage.Profile
}

var _ = Strategy(Local{})

func (l Local) EnsureCA(ctx context.Context, env *action.Environment) error {
	if err := setup.EnsureCA(env, nil, l.Profile, setup.DisallowNonInteractiveSetup); err != nil {
		return err
	}
	return nil
}

func (l Local) CASubject(ctx context.Context, env *action.Environment) *dname.Config {
	// Inherit CA subject iff CA is setup.
	now := env.NowImpl()
	if st := l.Profile.Status(now); st.Code == storage.ValidCA {
		return dname.FromPkixName(st.CACert.Subject)
	}
	return nil
}

func (Local) Issue(ctx context.Context, env *action.Environment, pub crypto.PublicKey, cfg *issue.Config) ([]byte, error) {
	return issue.Run(env, pub, cfg)
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
		profile, err := env.Profile()
		if err != nil {
			return err
		}

		return ActionImpl(Local{Profile: profile}, c)
	},
}
