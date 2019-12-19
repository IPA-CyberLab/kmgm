package serve

import (
	"time"

	"github.com/urfave/cli/v2"

	wcli "github.com/IPA-CyberLab/kmgm/cli"
	"github.com/IPA-CyberLab/kmgm/cli/serve"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var IssueHttpDefaultShutdown = 5 * time.Minute

var Command = &cli.Command{
	Name:    "serve",
	Usage:   "Start Komagome PKI HTTPS/gRPC API Server",
	Aliases: []string{"s", "srv"},
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:  "issue-http",
			Value: 0,
			Usage: "Enable certificate issue via HTTP API",
		},
		&cli.DurationFlag{
			Name:  "auto-shutdown",
			Value: time.Duration(0),
			Usage: "Auto shutdown server after specified time",
		},
		&cli.BoolFlag{
			Name:  "bootstrap",
			Usage: "Enable node bootstrapping via (generated) token.",
		},
		&cli.StringFlag{
			Name:  "bootstrap-token",
			Usage: "Enable node bootstrapping using the specified token.",
		},
	},
	Action: func(c *cli.Context) error {
		env := wcli.GlobalEnvironment

		cfg, err := serve.DefaultConfig()
		if err != nil {
			return err
		}
		cfg.IssueHttp = c.Int("issue-http")
		if c.IsSet("auto-shutdown") {
			cfg.AutoShutdown = c.Duration("auto-shutdown")
		} else {
			if cfg.IssueHttp > 0 {
				cfg.AutoShutdown = IssueHttpDefaultShutdown
			}
		}
		if c.IsSet("bootstrap") || c.IsSet("bootstrap-token") {
			cfg.Bootstrap = c.String("bootstrap-token")
			if cfg.Bootstrap == "" {
				token, err := wcrypto.GenBase64Token(env.Randr, env.Logger)
				if err != nil {
					return err
				}
				cfg.Bootstrap = token
			}
		}

		return serve.Run(c.Context, env, cfg)
	},
}
