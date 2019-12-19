package issue

import (
	"crypto"
	"fmt"

	"github.com/urfave/cli/v2"

	wcli "github.com/IPA-CyberLab/kmgm/cli"
	localissue "github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/remote/issue"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/structflags"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var Command = &cli.Command{
	Name:  "issue",
	Usage: "Issue a new certificate or renew an existing certificate. Generates private key if needed.",
	Flags: structflags.MustPopulateFlagsFromStruct(localissue.Config{}),
	Action: func(c *cli.Context) error {
		env := wcli.GlobalEnvironment
		if err := env.EnsureClientConn(c.Context); err != nil {
			return err
		}

		issuecfg, err := issue.DefaultConfig(env)
		if err != nil {
			return err
		}

		cfg := &localissue.Config{
			Issue: issuecfg,
		}

		if err := structflags.PopulateStructFromCliContext(cfg, c); err != nil {
			return err
		}

		var priv crypto.PrivateKey
		priv, cfg.PrivateKeyPath, err = localissue.ReadOrGenerateKey(env, cfg.Issue.KeyType, cfg.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("Failed to acquire private key: %w", err)
		}

		pub, err := wcrypto.ExtractPublicKey(priv)
		if err != nil {
			return err
		}

		cfg.CertPath, err = localissue.PromptCertPath(env, cfg.PrivateKeyPath, cfg.CertPath)
		if err != nil {
			return fmt.Errorf("Failed to acquire certificate file path: %w", err)
		}

		if err := frontend.EditStructWithVerifier(
			env.Frontend, localissue.ConfigTemplateText, cfg, frontend.CallVerifyMethod); err != nil {
			return err
		}

		certDer, err := issue.IssueCertificate(c.Context, env, pub, cfg.Issue)
		if err != nil {
			return err
		}

		if err := storage.WriteCertificateDerFile(cfg.CertPath, certDer); err != nil {
			return err
		}

		return nil
	},
}
