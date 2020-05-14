package show

import (
	"context"
	"crypto/x509"
	"strconv"

	"github.com/IPA-CyberLab/kmgm/action"
	localshow "github.com/IPA-CyberLab/kmgm/cmd/kmgm/show"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/urfave/cli/v2"
)

func FindCertificateWithPrefix(ctx context.Context, env *action.Environment, prefix string) (*x509.Certificate, error) {
	if err := env.EnsureClientConn(ctx); err != nil {
		return nil, err
	}

	sc := pb.NewCertificateServiceClient(env.ClientConn)

	var err error
	sn := int64(0)

	if prefix != "" && prefix != "ca" {
		sn, err = strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	// FIXME[P1] actually perform prefix match

	resp, err := sc.GetCertificate(ctx, &pb.GetCertificateRequest{
		Profile:      env.ProfileName,
		SerialNumber: sn,
	})
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(resp.Certificate)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

var Command = &cli.Command{
	Name:      "show",
	Usage:     "Show CA status, an existing certificate and/or its key.",
	UsageText: localshow.Command.UsageText,
	Flags:     localshow.Command.Flags,
	Action:    localshow.ActionImpl(FindCertificateWithPrefix),
}
