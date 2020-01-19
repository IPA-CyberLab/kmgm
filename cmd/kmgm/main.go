package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	action "github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/list"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/remote"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/serve"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/tool"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/ipapi"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/version"
)

func SimpleTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("15:04:05.999"))
}

func main() {
	defaultStoragePath, err := storage.DefaultStoragePath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get default basedir: %v", err)
		os.Exit(1)
		return
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
	}
	app.Commands = []*cli.Command{
		setup.Command,
		issue.Command,
		list.Command,
		remote.Command,
		serve.Command,
		tool.Command,
	}
	app.Before = func(c *cli.Context) error {
		if c.Bool("no-geoip") {
			ipapi.EnableQuery = false
		}

		cfg := zap.NewProductionConfig()
		cfg.DisableCaller = !c.Bool("log-location")
		if !c.Bool("log-json") {
			cfg.Encoding = "console"
			cfg.EncoderConfig.EncodeTime = SimpleTimeEncoder
			cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}
		if c.Bool("verbose") {
			cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		}

		logger, err := cfg.Build()
		if err != nil {
			return err
		}
		zap.ReplaceGlobals(logger)

		stor, err := storage.New(c.String("basedir"))
		if err != nil {
			return err
		}
		env, err := action.NewEnvironment(stor)
		if err != nil {
			return err
		}
		env.ProfileName = c.String("profile")

		configFile := c.String("config")
		if configFile != "" {
			bs, err := ioutil.ReadFile(configFile)
			if err != nil {
				return err
			}
			c.App.Metadata["ConfigBytes"] = bs
			env.Frontend = &frontend.NonInteractive{
				Logger: env.Logger,
			}
		}
		action.GlobalEnvironment = env

		return nil
	}
	app.After = func(c *cli.Context) error {
		zap.L().Sync()
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		zap.S().Fatal(err)
	}
}
