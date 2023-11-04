package batch

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/app/appflags"
	issuecmd "github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	setupcmd "github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/storage"
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

func Action(c *cli.Context) error {
	cfgbs, ok := c.App.Metadata["config"]
	if !ok {
		return ErrYamlMustBeProvided
	}

	af := c.App.Metadata["AppFlags"].(*appflags.AppFlags)

	env := action.GlobalEnvironment
	slog := env.Logger.Sugar()

	var cfg *Config
	if c.Bool("dump-template") || !af.NoDefault {
		slog.Infof("Constructing default config.")

		cfg = &Config{
			Setup: setupcmd.DefaultConfig(env),
		}
	} else {
		slog.Infof("Config is from scratch.")

		cfg = &Config{
			Setup: setupcmd.EmptyConfig(),
		}
	}

	decodeConfig := func() error {
		r := bytes.NewBuffer(cfgbs.([]byte))

		d := yaml.NewDecoder(r)
		d.KnownFields(true)

		return d.Decode(cfg)
	}
	if err := decodeConfig(); err != nil {
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

	if !af.NoDefault {
		slog.Infof("Rereading config with to process cert issue with updated defaults.")

		origTemplate := issuecmd.UnmarshalConfigTemplate
		defer func() {
			issuecmd.UnmarshalConfigTemplate = origTemplate
		}()

		now := env.NowImpl()
		st := profile.Status(now)
		if st.Code != storage.ValidCA {
			return fmt.Errorf("BUG: CA profile %q is not valid: %v", env.ProfileName, st)
		}
		baseSubject := dname.FromPkixName(st.CACert.Subject)
		issuecmd.UnmarshalConfigTemplate = &issuecmd.Config{
			Issue:       issue.DefaultConfig(baseSubject),
			RenewBefore: period.DaysAuto,
		}

		cfg = &Config{Setup: cfg.Setup}
		if err := decodeConfig(); err != nil {
			return err
		}
	}

	processIssue := func(issueCfg *issuecmd.Config) error {
		if issueCfg.PrivateKeyPath == "" {
			return fmt.Errorf("privateKeyPath must be specified")
		}
		if err := issuecmd.PrepareKeyTypePath(env, &issueCfg.Issue.KeyType, &issueCfg.PrivateKeyPath); err != nil {
			return err
		}

		if issueCfg.CertPath == "" {
			return fmt.Errorf("certPath must be specified")
		}
		newCertPath, err := issuecmd.PromptCertPath(env, issueCfg.PrivateKeyPath, issueCfg.CertPath)
		if err != nil {
			return err
		}
		issueCfg.CertPath = newCertPath

		if err := issueCfg.Verify(env, af.NoDefault); err != nil {
			return err
		}
		if err := issuecmd.IssuePrivateKeyAndCertificateFile(c.Context, env, issuecmd.Local{}, issueCfg); err != nil {
			return err
		}
		return nil
	}

	var merr error
	for i, issueCfg := range cfg.Issues {
		slog.Infof("batch: processing issue[%d]: %v", i, issueCfg.Issue.Subject)
		err := processIssue(issueCfg)
		if err != nil {
			slog.Errorf("batch: issue[%d]: %v", i, err)
			merr = multierr.Append(merr, fmt.Errorf("batch: issue[%d]: %w", i, err))
		}
	}

	return merr
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
