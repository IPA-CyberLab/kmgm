package bootstrap

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	action "github.com/IPA-CyberLab/kmgm/action"
	localissue "github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/action/serve/authprofile"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/frontend/validate"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/remote/issue"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

func EnsureKey(env *action.Environment) (crypto.PrivateKey, error) {
	slog := env.Logger.Sugar()
	privPath := env.Storage.ClientPrivateKeyPath()

	priv, err := storage.ReadPrivateKeyFile(privPath)
	if err == nil {
		slog.Infof("Using existing client private key %q.", privPath)
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := validate.MkdirAndCheckWritable(privPath); err != nil {
		return nil, err
	}
	priv, err = wcrypto.GenerateKey(env.Randr, wcrypto.ServerKeyType, "clientauth", env.Logger)
	if err != nil {
		return nil, err
	}
	if err := storage.WritePrivateKeyFile(privPath, priv); err != nil {
		return nil, err
	}
	slog.Infof("Wrote client private key to %q.", privPath)
	return priv, nil
}

func IssueCertPair(ctx context.Context, env *action.Environment) error {
	slog := env.Logger.Sugar()

	priv, err := EnsureKey(env)
	if err != nil {
		return err
	}

	certPath := env.Storage.ClientCertPath()
	_, err = storage.ReadCertificateFile(certPath)
	if err == nil {
		slog.Warnf("Existing kmgm client cert found. Not requesting new cert.")
		slog.Warnf("To force re-bootstrapping, delete file %q and try again.", certPath)

		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Error when reading existing client auth cert %q. Try removing the file and retry: %w", certPath, err)
	}
	if err := validate.MkdirAndCheckWritable(certPath); err != nil {
		return err
	}

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	cfg := &localissue.Config{
		Subject: &dname.Config{
			CommonName: hostname,
		},
		KeyUsage: keyusage.KeyUsageTLSClient,
		Validity: localissue.FarFuture,
		KeyType:  wcrypto.ServerKeyType,
	}
	certDer, err := issue.IssueCertificate(ctx, env, pub, cfg)
	if err != nil {
		return err
	}

	if err := storage.WriteCertificateDerFile(certPath, certDer); err != nil {
		return err
	}
	slog.Infof("Wrote issued client cert to %q.", certPath)
	return nil
}

var Command = &cli.Command{
	Name:  "bootstrap",
	Usage: "Register this client to the kmgm HTTPS/gRPC server",
	Flags: []cli.Flag{},
	Action: func(c *cli.Context) error {
		env := action.GlobalEnvironment
		slog := env.Logger.Sugar()

		if env.ProfileName != storage.DefaultProfileName &&
			env.ProfileName != authprofile.ProfileName {
			slog.Warnf("Specified --profile %q setting is ignored in bootstrap cmd.", env.ProfileName)
		}
		env.ProfileName = authprofile.ProfileName

		if err := env.EnsureClientConn(c.Context); err != nil {
			return err
		}
		if err := IssueCertPair(c.Context, env); err != nil {
			return err
		}

		// Rewrite ConnectionInfo to use the issued client certificate instead of bootstrap token.
		env.ConnectionInfo.AccessToken = ""
		env.ConnectionInfo.ClientCertificateFile = env.Storage.ClientCertPath()
		env.ConnectionInfo.ClientPrivateKeyFile = env.Storage.ClientPrivateKeyPath()

		if err := env.SaveConnectionInfo(); err != nil {
			return err
		}

		return nil
	},
}
