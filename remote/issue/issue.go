package issue

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/IPA-CyberLab/kmgm/cli"
	localissue "github.com/IPA-CyberLab/kmgm/cli/issue"
	"github.com/IPA-CyberLab/kmgm/pb"
)

type Config = localissue.Config

var DefaultConfig = localissue.DefaultConfig

func IssueCertificate(ctx context.Context, env *cli.Environment, pub crypto.PublicKey, cfg *Config) ([]byte, error) {
	slog := env.Logger.Sugar()

	if err := cfg.Names.Verify(); err != nil {
		return nil, err
	}

	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	sc := pb.NewCertificateServiceClient(env.ClientConn)

	slog.Info("Requesting certificate...")
	start := time.Now()
	resp, err := sc.IssueCertificate(ctx, &pb.IssueCertificateRequest{
		PublicKey:        pkixpub,
		Subject:          cfg.Subject.ToProtoStruct(),
		Names:            cfg.Names.ToProtoStruct(),
		NotAfterUnixtime: cfg.Validity.GetNotAfter(start).Unix(),
		KeyUsage:         cfg.KeyUsage.ToProtoStruct(),
		Profile:          env.ProfileName,
	})
	slog.Infow("Generating certificate... Done.", "took", time.Now().Sub(start))
	if err != nil {
		return nil, err
	}
	return resp.Certificate, nil
}
