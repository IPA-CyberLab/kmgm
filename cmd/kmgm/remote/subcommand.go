package remote

import (
	"github.com/urfave/cli/v2"

	action "github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/remote/bootstrap"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/remote/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/remote/version"
	"github.com/IPA-CyberLab/kmgm/remote"
	"github.com/IPA-CyberLab/kmgm/structflags"
)

var Command = &cli.Command{
	Name:    "client",
	Aliases: []string{"c", "cli"},
	Usage:   "Interact with remote CA",
	Flags:   structflags.MustPopulateFlagsFromStruct(remote.ConnectionInfo{}),
	Before: func(c *cli.Context) error {
		env := action.GlobalEnvironment
		if err := env.LoadConnectionInfo(); err != nil {
			return err
		}
		if err := structflags.PopulateStructFromCliContext(&env.ConnectionInfo, c); err != nil {
			return err
		}

		return nil
	},
	Subcommands: []*cli.Command{
		bootstrap.Command,
		issue.Command,
		version.Command,
	},
}
