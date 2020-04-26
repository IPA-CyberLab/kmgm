package issue

import (
	"github.com/urfave/cli/v2"

	"github.com/IPA-CyberLab/kmgm/action"
	localissue "github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/remote/issue"
	"github.com/IPA-CyberLab/kmgm/structflags"
)

func remoteCASubject(env *action.Environment) *dname.Config {
	// FIXME[P2]: Implement me
	return nil
}

var Command = &cli.Command{
	Name:   "issue",
	Usage:  "Issue a new certificate or renew an existing certificate. Generates private key if needed.",
	Flags:  structflags.MustPopulateFlagsFromStruct(localissue.Config{}),
	Action: localissue.ActionImpl(remoteCASubject, issue.IssueCertificate),
}
