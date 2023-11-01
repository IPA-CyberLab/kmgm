package batch

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/app/appflags"
	issuecmd "github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	setupcmd "github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/structflags"
)

const ConfigTemplateText = `
---
# kmgm pki batch config

profile: [profile]

setup:


# FIXME
`

type Config struct {
	Setup *setupcmd.Config `yaml:",inline"`

	Issues []*issuecmd.Config `yaml:"issues"`

	// XXX_AppFlags is not here, since setup.Config covers that.
}

var ErrYamlMustBeProvided = errors.New("batch: yaml config must be provided. Try `kmgm -c [config.yaml] batch`")
var ErrMustUseNoDefault = errors.New("batch: must use noDefault mode.")

func Action(c *cli.Context) error {
	cfgbs, ok := c.App.Metadata["config"]
	if !ok {
		return ErrYamlMustBeProvided
	}

	af := c.App.Metadata["AppFlags"].(*appflags.AppFlags)
	if !af.NoDefault {
		return ErrMustUseNoDefault
	}

	env := action.GlobalEnvironment
	slog := env.Logger.Sugar()

	if c.Bool("dump-template") {
		cfg := &Config{
			Setup: setupcmd.DefaultConfig(env),
		}
		if err := frontend.DumpTemplate(ConfigTemplateText, cfg); err != nil {
			return err
		}
		return nil
	}

	slog.Debugf("batch config is always constructed from scratch.")
	cfg := &Config{Setup: setupcmd.EmptyConfig()}

	r := bytes.NewBuffer(cfgbs.([]byte))

	d := yaml.NewDecoder(r)
	d.KnownFields(true)

	if err := d.Decode(cfg); err != nil {
		return err
	}

	profile, err := env.Profile()
	if err != nil {
		return err
	}

	if err := setupcmd.EnsureCA(env, cfg.Setup, profile, setupcmd.AllowNonInteractiveSetupAndRequireCompatibleConfig); err != nil {
		return err
	}
	if err := setupcmd.CopyCACert(env, cfg.Setup, profile); err != nil {
		return err
	}

	for i, issueCfg := range cfg.Issues {
		slog.Infof("batch: processing issue[%d]: %v", i, issueCfg.Issue.Subject)

		if issueCfg.PrivateKeyPath == "" {
			return fmt.Errorf("batch: issue[%d]: privateKeyPath must be specified", i)
		}
		if err := issuecmd.PrepareKeyTypePath(env, &issueCfg.Issue.KeyType, &issueCfg.PrivateKeyPath); err != nil {
			return fmt.Errorf("batch: issue[%d]: %w", i, err)
		}

		if issueCfg.CertPath == "" {
			return fmt.Errorf("batch: issue[%d]: certPath must be specified", i)
		}
		newCertPath, err := issuecmd.PromptCertPath(env, issueCfg.PrivateKeyPath, issueCfg.CertPath)
		if err != nil {
			return fmt.Errorf("batch: issue[%d]: %w", i, err)
		}
		issueCfg.CertPath = newCertPath

		if err := issueCfg.Verify(env, af.NoDefault); err != nil {
			return fmt.Errorf("batch: issue[%d]: %w", i, err)
		}
		if err := issuecmd.IssuePrivateKeyAndCertificateFile(c.Context, env, issuecmd.Local{}, issueCfg); err != nil {
			return fmt.Errorf("batch: issue[%d]: %w", i, err)
		}
	}

	return nil
}

var Command = &cli.Command{
	Name:  "batch",
	Usage: "Processes a set of kmgm commands.",
	Flags: append(structflags.MustPopulateFlagsFromStruct(Config{}),
		&cli.BoolFlag{
			Name:  "dump-template",
			Usage: "dump configuration template yaml without making actual changes",
		},
	),
	Action: Action,
}
