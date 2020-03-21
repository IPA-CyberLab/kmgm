package setup

import (
	"github.com/urfave/cli/v2"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/setup"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/structflags"
)

// FIXME[P2]: Should escape
const configTemplateText = `
---
# kmgm PKI CA config
subject:
  commonName: {{ .Subject.CommonName }}
  organization: {{ .Subject.Organization }}
  organizationalUnit: {{ .Subject.OrganizationalUnit }}
  country: {{ .Subject.Country }}
  locality: {{ .Subject.Locality }}
  province: {{ .Subject.Province }}
  streetAddress: {{ .Subject.StreetAddress }}
  postalCode: {{ .Subject.PostalCode }}

keyType: {{ .KeyType }}
`

func EnsureCA(env *action.Environment, cfg *setup.Config, profile *storage.Profile) error {
	slog := env.Logger.Sugar()

	st := profile.Status()
	if st == nil {
		slog.Infof("%v already has a CA setup.", profile)
		return nil
	}
	if st.Code != storage.NotCA {
		return st
	}

	if cfg == nil {
		var err error
		cfg, err = setup.DefaultConfig()
		// setup.DefaultConfig errors are ignorable.
		if err != nil {
			slog.Debugf("Errors encountered while constructing default CA config: %v", err)
		}
	}

	slog.Infof("Starting CA setup for %v.", profile)
	if err := frontend.EditStructWithVerifier(
		env.Frontend, configTemplateText, cfg, frontend.CallVerifyMethod); err != nil {
		return err
	}

	if err := setup.Run(env, cfg); err != nil {
		return err
	}
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

		// FIXME[P1]: noDefault
		cfg, err := setup.DefaultConfig()
		if c.Bool("dump-template") {
			if err := frontend.DumpTemplate(configTemplateText, cfg); err != nil {
				return err
			}
			return nil
		}
		// setup.DefaultConfig errors are ignorable.
		if err != nil {
			slog.Debugf("Errors encountered while constructing default config: %v", err)
		}

		// FIXME[P1]: This must come after EditStructWithVerifier.
		if err := structflags.PopulateStructFromCliContext(cfg, c); err != nil {
			return err
		}

		profile, err := env.Profile()
		if err != nil {
			return err
		}

		if err := EnsureCA(env, cfg, profile); err != nil {
			return err
		}

		return nil
	},
}
