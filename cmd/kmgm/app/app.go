package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/app/appflags"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/batch"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/list"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/remote"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/serve"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/show"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/tool"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/frontend/promptuife"
	"github.com/IPA-CyberLab/kmgm/ipapi"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/structflags"
	"github.com/IPA-CyberLab/kmgm/version"
)

func SimpleTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("15:04:05.999"))
}

func mustFindFlagByName(fs []cli.Flag, name string) cli.Flag {
	l := zap.S()
	for _, f := range fs {
		if f.Names()[0] == name {
			return f
		}
	}

	l.Panic("Failed to find flag of name %q", name)
	return nil
}

func resolveCmd(c *cli.Context) *cli.Command {
	app := c.App

	args := c.Args()
	if !args.Present() {
		return nil
	}

	name := args.First()
	return app.Command(name)
}

func New() *cli.App {
	defaultStoragePath, err := storage.DefaultStoragePath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get default basedir: %v", err)
		os.Exit(1)
		return nil
	}

	app := cli.NewApp()
	app.Name = "Komagome PKI"
	app.Usage = "PKI for your own cluster"
	app.Authors = []*cli.Author{
		{Name: "yzp0n", Email: "yzp0n@coe.ad.jp"},
	}
	app.Version = fmt.Sprintf("%s.%s", version.Version, version.Commit)
	app.EnableBashCompletion = true

	af := appflags.AppFlags{
		BaseDir: defaultStoragePath,
		Profile: storage.DefaultProfileName,
	}
	app.Flags = structflags.MustPopulateFlagsFromStruct(&af)
	app.Metadata = map[string]interface{}{
		"AppFlags": &af,
	}

	basedirFlag := mustFindFlagByName(app.Flags, "basedir")
	basedirStringFlag := basedirFlag.(*cli.StringFlag)
	basedirStringFlag.EnvVars = []string{"KMGMDIR"}

	profileFlag := mustFindFlagByName(app.Flags, "profile")
	profileStringFlag := profileFlag.(*cli.StringFlag)
	profileStringFlag.EnvVars = []string{"KMGM_PROFILE"}

	app.Commands = []*cli.Command{
		setup.Command,
		issue.Command,
		batch.Command,
		list.Command,
		remote.Command,
		serve.Command,
		tool.Command,
		show.Command,
	}
	BeforeImpl := func(c *cli.Context) error {
		cmd := resolveCmd(c)
		if cmd == batch.Command {
			af.NoDefault = true
			af.NonInteractive = true
		}

		if err := structflags.PopulateStructFromCliContext(&af, c); err != nil {
			return err
		}

		if af.NoGeoIp {
			ipapi.EnableQuery = false
		}

		var logger *zap.Logger
		if loggeri, ok := app.Metadata["Logger"]; ok {
			logger = loggeri.(*zap.Logger)
		} else {
			cfg := zap.NewProductionConfig()
			cfg.DisableCaller = !af.LogLocation
			if !af.LogJson {
				cfg.Encoding = "console"
				switch cmd {
				case serve.Command:
					cfg.EncoderConfig.EncodeTime = SimpleTimeEncoder
				default:
					cfg.EncoderConfig.TimeKey = ""
				}

				cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			}
			if af.Verbose {
				cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
			}

			logger, err = cfg.Build(
				zap.AddStacktrace(zap.NewAtomicLevelAt(zap.DPanicLevel)))
			if err != nil {
				return err
			}
		}
		zap.ReplaceGlobals(logger)

		if af.Config != "" {
			var r io.ReadCloser
			if af.Config == "-" {
				r = os.Stdin
			} else {
				f, err := os.Open(af.Config)
				if err != nil {
					return fmt.Errorf("Failed to open specified config file %q: %w", af.Config, err)
				}
				r = f
			}

			bs, err := io.ReadAll(r)
			if err != nil {
				return fmt.Errorf("Failed to read specified config file %q: %w", af.Config, err)
			}
			if err := r.Close(); err != nil {
				return fmt.Errorf("Failed to close specified config file %q: %w", af.Config, err)
			}

			configText := string(bs)
			if strings.TrimSpace(configText) == "" {
				return fmt.Errorf("The specified config file %s was empty", af.Config)
			}
			app.Metadata["config"] = bs

			af.NonInteractive = true

			if err := yaml.Unmarshal(bs, &af); err != nil {
				return fmt.Errorf("Failed to yaml.Unmarshal AppFlags: %w", err)
			}
		}

		stor, err := storage.New(af.BaseDir)
		if err != nil {
			return err
		}

		var fe frontend.Frontend
		if af.NonInteractive || !isatty.IsTerminal(os.Stdin.Fd()) {
			fe = &frontend.NonInteractive{Logger: logger}
		} else {
			fe = promptuife.Frontend{}
		}

		env, err := action.NewEnvironment(fe, stor)
		if err != nil {
			return err
		}
		env.ProfileName = af.Profile
		env.Logger = logger
		if nowimpl, ok := app.Metadata["NowImpl"]; ok {
			env.NowImpl = nowimpl.(func() time.Time)
		}

		action.GlobalEnvironment = env

		return nil
	}
	app.Before = func(c *cli.Context) error {
		if err := BeforeImpl(c); err != nil {
			// Print error message to stderr
			app.Writer = app.ErrWriter

			// Suppress help message on app.Before() failure.
			cli.HelpPrinter = func(_ io.Writer, _ string, _ interface{}) {}
			return err
		}

		return nil
	}
	app.After = func(c *cli.Context) error {
		zap.L().Sync()
		return nil
	}

	return app
}
