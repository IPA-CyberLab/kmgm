package version

import (
	"context"

	"github.com/urfave/cli/v2"

	wcli "github.com/IPA-CyberLab/kmgm/cli"
	"github.com/IPA-CyberLab/kmgm/pb"
)

func queryVersion(ctx context.Context, env *wcli.Environment) error {
	slog := env.Logger.Sugar()

	sc := pb.NewVersionServiceClient(env.ClientConn)
	resp, err := sc.GetVersion(ctx, &pb.GetVersionRequest{})
	if err != nil {
		return err
	}
	slog.Infof("Version: %s", resp.Version)
	slog.Infof("Commit: %s", resp.Commit)

	return nil
}

var Command = &cli.Command{
	Name:  "version",
	Usage: "Query remote CA kmgm version",
	Action: func(c *cli.Context) error {
		env := wcli.GlobalEnvironment
		if err := env.EnsureClientConn(c.Context); err != nil {
			return err
		}

		return queryVersion(c.Context, env)
	},
}
