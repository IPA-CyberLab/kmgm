package app

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/IPA-CyberLab/kmgm/action"
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
	"github.com/IPA-CyberLab/kmgm/version"
	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func SimpleTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("15:04:05.999"))
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
	app.Flags = []cli.Flag{
		&cli.PathFlag{
			Name:    "basedir",
			EnvVars: []string{"KMGMDIR"},
			Usage:   "The root directory storing all kmgm data.",
			Value:   defaultStoragePath,
		},
		&cli.StringFlag{
			Name:    "profile",
			EnvVars: []string{"KMGM_PROFILE"},
			Usage:   "Name of the profile to operate against.",
			Value:   storage.DefaultProfileName,
		},
		&cli.StringFlag{
			Name:  "config",
			Usage: "Read the specified YAML config file instead of interactive prompt.",
		},
		&cli.BoolFlag{
			Name:  "no-geoip",
			Usage: "Disable querying ip-api.com for geolocation data.",
		},
		&cli.BoolFlag{
			Name:  "no-default",
			Usage: "Disable populating default values on non-interactive mode.",
		},
		&cli.BoolFlag{
			Name:  "log-location",
			Usage: "Annotate logs with code location where the log was output",
		},
		&cli.BoolFlag{
			Name:  "log-json",
			Usage: "Format logs in json",
		},
		&cli.BoolFlag{
			Name:  "verbose",
			Usage: "Enable verbose output",
		},
		&cli.BoolFlag{
			Name:  "non-interactive",
			Usage: "Use non-interactive frontend, which auto proceeds with default answers.",
		},
	}
	app.Commands = []*cli.Command{
		setup.Command,
		issue.Command,
		list.Command,
		remote.Command,
		serve.Command,
		tool.Command,
		show.Command,
	}
	BeforeImpl := func(c *cli.Context) error {
		cmd := resolveCmd(c)

		if c.Bool("no-geoip") {
			ipapi.EnableQuery = false
		}

		var logger *zap.Logger
		if loggeri, ok := app.Metadata["Logger"]; ok {
			logger = loggeri.(*zap.Logger)
		} else {
			cfg := zap.NewProductionConfig()
			cfg.DisableCaller = !c.Bool("log-location")
			if !c.Bool("log-json") {
				cfg.Encoding = "console"
				switch cmd {
				case serve.Command:
					cfg.EncoderConfig.EncodeTime = SimpleTimeEncoder
				default:
					cfg.EncoderConfig.TimeKey = ""
				}

				cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			}
			if c.Bool("verbose") {
				cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
			}

			logger, err = cfg.Build(
				zap.AddStacktrace(zap.NewAtomicLevelAt(zap.DPanicLevel)))
			if err != nil {
				return err
			}
		}

		stor, err := storage.New(c.String("basedir"))
		if err != nil {
			return err
		}

		configFile := c.String("config")
		if configFile != "" {
			bs, err := ioutil.ReadFile(configFile)
			if err != nil {
				return fmt.Errorf("Failed to read specified config file: %w", err)
			}
			configText := string(bs)
			if strings.TrimSpace(configText) == "" {
				return fmt.Errorf("The specified config file %s was empty", configFile)
			}
			app.Metadata["config"] = bs

			if frontend.IsNoDefaultSpecifiedInYaml(bs) {
				logger.Debug("The specified config file has NoDefault set to true.")
				c.Set("no-default", "true")
			}

			c.Set("non-interactive", "true")
		}

		var fe frontend.Frontend
		if c.Bool("non-interactive") || !isatty.IsTerminal(os.Stdin.Fd()) {
			fe = &frontend.NonInteractive{Logger: logger}
		} else {
			fe = promptuife.Frontend{}
		}

		env, err := action.NewEnvironment(fe, stor)
		if err != nil {
			return err
		}
		env.ProfileName = c.String("profile")
		env.Logger = logger
		if nowimpl, ok := app.Metadata["NowImpl"]; ok {
			env.NowImpl = nowimpl.(func() time.Time)
		}

		action.GlobalEnvironment = env
		zap.ReplaceGlobals(env.Logger)

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
