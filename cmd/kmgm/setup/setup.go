package setup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/setup"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/app/appflags"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/ipapi"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/structflags"
)

type Config struct {
	Setup *setup.Config `yaml:"setup" flags:""`

	CopyCACertPath string `yaml:"copyCACertPath" flags:"copy-ca-cert-path,copy CA cert to the specified path,,path"`

	// This is here to avoid yaml.v3 Decoder with KnownFields(true) throwing error for valid AppFlags fields
	XXX_AppFlags appflags.AppFlags `yaml:",inline"`
}

func (c *Config) Verify(env *action.Environment) error {
	if err := c.Setup.Verify(env.NowImpl()); err != nil {
		return err
	}

	return nil
}

func DefaultConfig(env *action.Environment) *Config {
	slog := env.Logger.Sugar()

	geo, err := ipapi.QueryCached(env.Storage.GeoIpCachePath(), env.Logger)
	if err != nil {
		slog.Infof("ipapi.QueryCached: %v", err)
	}
	if geo == nil {
		geo = &ipapi.Result{}
	}

	return &Config{Setup: setup.DefaultConfig(dname.FromGeoip(geo))}
}

func EmptyConfig() *Config {
	return &Config{Setup: setup.EmptyConfig()}
}

const configTemplateText = `
---
# kmgm PKI CA config
setup:
{{ with .Setup }}
  {{ template "subject" .Subject }}

  # validity specifies the lifetime the ca is valid for.
  validity: {{ printf "%v" .Validity }}
  # validity: 30d # valid for 30 days from now.
  # validity: 2y # valid for 2 years from now.
  # validity: 20220530 # valid until yyyyMMdd.
  # validity: farfuture # valid effectively forever

  keyType: {{ .KeyType }}

  # For advanced users only.
  #   nameConstraints allow CA to scope subjectAltNames of its leaf certificates.
  #   https://tools.ietf.org/html/rfc5280#section-4.2.1.10
  nameConstraints:
  {{- range .NameConstraints.Strings }}
    - {{ . | YamlEscapeString }}
  {{- end -}}
{{ end -}}
`

var CantRunInteractiveCASetupErr = errors.New("EnsureCA: Could not resort to interactive CA setup: non-interactive frontend.")

type EnsureCAMode int

const (
	DisallowNonInteractiveSetup EnsureCAMode = iota
	AllowNonInteractiveSetup
	AllowNonInteractiveSetupAndRequireCompatibleConfig
)

type IncompatibleCertErr struct {
	Wrap error
}

func (e IncompatibleCertErr) Error() string {
	return fmt.Sprintf("CA setup requested, but existing CA cert was issued with a different config. Please specify a matching config or reset existing CA: %v", e.Wrap)
}

func (IncompatibleCertErr) Is(target error) bool {
	_, ok := target.(IncompatibleCertErr)
	return ok
}

func (e IncompatibleCertErr) Unwrap() error {
	return e.Wrap
}

func EnsureCA(env *action.Environment, cfg *Config, profile *storage.Profile, mode EnsureCAMode) error {
	slog := env.Logger.Sugar()

	now := env.NowImpl()
	if st := profile.Status(now); st.Code == storage.ValidCA {
		if mode == AllowNonInteractiveSetupAndRequireCompatibleConfig {
			certCfg, err := setup.ConfigFromCert(st.CACert)
			if err != nil {
				return IncompatibleCertErr{Wrap: err}
			}

			if err := cfg.Setup.CompatibleWith(certCfg); err != nil {
				return IncompatibleCertErr{Wrap: err}
			}
		}

		slog.Infof("%v already has a CA setup.", profile)
		return nil
	} else if st.Code != storage.NotCA {
		return st
	}

	if mode == DisallowNonInteractiveSetup && !env.Frontend.IsInteractive() {
		return CantRunInteractiveCASetupErr
	}

	if cfg == nil {
		cfg = DefaultConfig(env)
	}

	slog.Infof("Starting CA setup for %v.", profile)
	if err := frontend.EditStructWithVerifier(
		env.Frontend, configTemplateText, cfg, func(cfgI interface{}) error {
			cfg := cfgI.(*Config)
			if err := cfg.Verify(env); err != nil {
				return err
			}
			return nil
		}); err != nil {
		return err
	}

	if err := setup.Run(env, cfg.Setup); err != nil {
		return err
	}
	slog.Infof("CA setup successfully completed for %v", profile)
	return nil
}

func CopyCACert(env *action.Environment, cfg *Config, profile *storage.Profile) error {
	slog := env.Logger.Sugar()

	if cfg.CopyCACertPath == "" {
		slog.Debugf("CopyCACertPath is not set. Skipping CA cert copy.")
		return nil
	}

	if st := profile.Status(env.NowImpl()); st.Code != storage.ValidCA {
		return fmt.Errorf("CA status is not valid: %v", st)
	}

	cacertpath := profile.CACertPath()
	cacertbs, err := os.ReadFile(cacertpath)
	if err != nil {
		return fmt.Errorf("Failed to read CA cert: %w", err)
	}

	if st, err := os.Stat(cfg.CopyCACertPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("copyCACertPath %q is not a regular file", cfg.CopyCACertPath)
		}

		existingbs, err := os.ReadFile(cfg.CopyCACertPath)
		if err != nil {
			return fmt.Errorf("Failed to read existing file %q at copyCACertPath: %w", cfg.CopyCACertPath, err)
		}
		if bytes.Equal(existingbs, cacertbs) {
			slog.Infof("Up to date CA cert already exists at %q. Skipping write.", cfg.CopyCACertPath)
			return nil
		}
	}

	dirpath := path.Dir(cfg.CopyCACertPath)
	if err := os.MkdirAll(dirpath, 0755); err != nil {
		return fmt.Errorf("Failed to mkdir %q: %w", dirpath, err)
	}

	if err := os.WriteFile(cfg.CopyCACertPath, cacertbs, 0644); err != nil {
		return fmt.Errorf("Failed to write CA cert: %w", err)
	}
	return nil
}

var Command = &cli.Command{
	Name:  "setup",
	Usage: "Setup Komagome PKI",
	Flags: append(structflags.MustPopulateFlagsFromStruct(&Config{}),
		&cli.BoolFlag{
			Name:  "dump-template",
			Usage: "dump configuration template yaml without making actual changes",
		},
	),
	Action: func(c *cli.Context) error {
		env := action.GlobalEnvironment
		slog := env.Logger.Sugar()

		af := c.App.Metadata["AppFlags"].(*appflags.AppFlags)

		profile, err := env.Profile()
		if err != nil {
			return err
		}

		slog.Debugf("config dump: %+v", af)

		var cfg *Config
		if c.Bool("dump-template") || !af.NoDefault {
			slog.Debugf("Constructing default config.")
			cfg = DefaultConfig(env)
		} else {
			slog.Debugf("Config is from scratch.")
			cfg = &Config{Setup: setup.EmptyConfig()}
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
			if err := frontend.DumpTemplate(configTemplateText, cfg); err != nil {
				return err
			}
			return nil
		}

		mode := AllowNonInteractiveSetup
		if af.NoDefault {
			mode = AllowNonInteractiveSetupAndRequireCompatibleConfig
		}
		if err := EnsureCA(env, cfg, profile, mode); err != nil {
			return err
		}
		if err := CopyCACert(env, cfg, profile); err != nil {
			return err
		}

		return nil
	},
}
