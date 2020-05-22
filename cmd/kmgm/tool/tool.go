package tool

import (
	"github.com/urfave/cli/v2"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/tool/dump"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/tool/pubkeyhash"
)

var Command = &cli.Command{
	Name:    "tool",
	Usage:   "misc tools",
	Aliases: []string{"t"},
	Subcommands: []*cli.Command{
		pubkeyhash.Command,
		dump.Command,
	},
}
