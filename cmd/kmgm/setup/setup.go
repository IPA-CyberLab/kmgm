package setup

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"

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

	// This is here to avoid UnmarshalStrict throw error for valid AppFlags fields
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

var CantRunInteractiveCASetupErr = errors.New("EnsureCA: Could not resort to interactive CA setupnon-interactive frontend.")

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
			if err := yaml.UnmarshalStrict(cfgbs.([]byte), cfg); err != nil {
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

		return nil
	},
}
