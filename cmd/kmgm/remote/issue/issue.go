package issue

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/urfave/cli/v2"

	"github.com/IPA-CyberLab/kmgm/action"
	localissue "github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/remote/issue"
	"github.com/IPA-CyberLab/kmgm/structflags"
)

type Remote struct {
}

var _ = localissue.Strategy(Remote{})

func (Remote) EnsureCA(ctx context.Context, env *action.Environment) error {
	if err := env.EnsureClientConn(ctx); err != nil {
		return err
	}

	sc := pb.NewCertificateServiceClient(env.ClientConn)
	resp, err := sc.IssuePreflight(ctx, &pb.IssuePreflightRequest{
		Profile: env.ProfileName,
	})
	if err != nil {
		return err
	}
	_ = resp

	return nil
}

func (Remote) CACert(ctx context.Context, env *action.Environment) *x509.Certificate {
	slog := env.Logger.Sugar()

	if err := env.EnsureClientConn(ctx); err != nil {
		slog.Debugf("CASubject: EnsureClientConn: %v", err)
		return nil
	}

	sc := pb.NewCertificateServiceClient(env.ClientConn)
	resp, err := sc.GetCertificate(ctx, &pb.GetCertificateRequest{
		Profile:      env.ProfileName,
		SerialNumber: 0,
	})
	if err != nil {
		slog.Debugf("CASubject: GetCertificate: %v", err)
		return nil
	}
	cert, err := x509.ParseCertificate(resp.Certificate)
	if err != nil {
		slog.Debugf("CASubject: ParseCertificate: %v", err)
		return nil
	}

	return cert
}

func (Remote) Issue(ctx context.Context, env *action.Environment, pub crypto.PublicKey, cfg *issue.Config) ([]byte, error) {
	return issue.IssueCertificate(ctx, env, pub, cfg)
}

var Command = &cli.Command{
	Name:  "issue",
	Usage: "Issue a new certificate or renew an existing certificate. Generates private key if needed.",
	Flags: structflags.MustPopulateFlagsFromStruct(localissue.Config{}),
	Action: func(c *cli.Context) error {
		return localissue.ActionImpl(Remote{}, c)
	},
}
