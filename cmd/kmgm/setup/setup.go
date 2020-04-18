package setup

import (
	"errors"

	"github.com/urfave/cli/v2"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/setup"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/structflags"
)

type Config struct {
	Setup *setup.Config `yaml:"setup" flags:""`

	// This is here to avoid UnmarshalStrict throw error when noDefault was specified for ShouldLoadDefaults().
	XXX_NoDefault bool `yaml:"noDefault"`
}

func (c *Config) Verify(env *action.Environment) error {
	if err := c.Setup.Verify(env.NowImpl()); err != nil {
		return err
	}

	return nil
}

// FIXME[P2]: Should escape
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
{{ end -}}
`

var ErrCantRunInteractiveCaSetup = errors.New("EnsureCA: Could not resort to interactive CA setup due to non-interactive frontend.")

func EnsureCA(env *action.Environment, cfg *Config, profile *storage.Profile, isSetupCommand bool) error {
	slog := env.Logger.Sugar()

	now := env.NowImpl()
	st := profile.Status(now)
	if st == nil {
		slog.Infof("%v already has a CA setup.", profile)
		return nil
	}
	if st.Code != storage.NotCA {
		return st
	}
	if !isSetupCommand && !env.Frontend.IsInteractive() {
		return ErrCantRunInteractiveCaSetup
	}

	if cfg == nil {
		setupcfg, err := setup.DefaultConfig()
		// setup.DefaultConfig errors are ignorable.
		if err != nil {
			slog.Debugf("Errors encountered while constructing default CA config: %v", err)
		}

		cfg = &Config{Setup: setupcfg}
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
	Flags: append(structflags.MustPopulateFlagsFromStruct(setup.Config{}),
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

			setupcfg, err := setup.DefaultConfig()
			// setup.DefaultConfig errors are ignorable.
			if err != nil {
				slog.Debugf("Errors encountered while constructing default config: %v", err)
			}

			cfg.Setup = setupcfg
		} else {
			slog.Debugf("Config is from scratch.")
			cfg.Setup = setup.EmptyConfig()
		}

		if c.Bool("dump-template") {
			if err := frontend.DumpTemplate(configTemplateText, cfg); err != nil {
				return err
			}
			return nil
		}

		// FIXME[P1]: This must come after EditStructWithVerifier.
		if err := structflags.PopulateStructFromCliContext(cfg, c); err != nil {
			return err
		}

		if err := EnsureCA(env, cfg, profile, true); err != nil {
			return err
		}

		return nil
	},
}
