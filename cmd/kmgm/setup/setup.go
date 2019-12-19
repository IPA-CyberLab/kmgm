package setup

import (
	"github.com/urfave/cli/v2"

	wcli "github.com/IPA-CyberLab/kmgm/cli"
	"github.com/IPA-CyberLab/kmgm/cli/setup"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/storage"
)

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
`

func PromptConfig(env *wcli.Environment) (*setup.Config, error) {
	cfg, err := setup.DefaultConfig()
	if err != nil {
		return nil, err
	}

	if err := frontend.EditStructWithVerifier(
		env.Frontend, configTemplateText, cfg, frontend.CallVerifyMethod); err != nil {
		return nil, err
	}

	return cfg, nil
}

func EnsureCA(env *wcli.Environment, profile *storage.Profile) error {
	slog := env.Logger.Sugar()

	st := profile.Status()
	if st == nil {
		slog.Infof("%v already has a CA setup.", profile)
		return nil
	}
	if st.Code != storage.NotCA {
		return st
	}

	slog.Infof("Starting CA setup for %v.", profile)
	cfg, err := PromptConfig(env)
	if err != nil {
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
	Action: func(c *cli.Context) error {
		env := wcli.GlobalEnvironment
		profile, err := env.Profile()
		if err != nil {
			return err
		}

		if err := EnsureCA(env, profile); err != nil {
			return err
		}

		return nil
	},
}
