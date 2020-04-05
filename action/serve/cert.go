package serve

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/action/serve/authprofile"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/validityperiod"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

func ensurePrivateKey(env *action.Environment, authp *storage.Profile) (crypto.PrivateKey, error) {
	priv, err := authp.ReadServerPrivateKey()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		priv, err := wcrypto.GenerateKey(env.Randr, wcrypto.ServerKeyType, "server ", env.Logger)
		if err != nil {
			return nil, err
		}
		if err := authp.WriteServerPrivateKey(priv); err != nil {
			return nil, err
		}

		return priv, nil
	}

	return priv, nil
}

func ensureServerCert(env *action.Environment, authp *storage.Profile, ns san.Names) (*tls.Certificate, string, error) {
	priv, err := ensurePrivateKey(env, authp)
	if err != nil {
		return nil, "", err
	}
	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		return nil, "", err
	}

	now := time.Now()

	cacert, err := authp.ReadCACertificate()
	if err != nil {
		return nil, "", err
	}
	if err := wcrypto.VerifyCACert(cacert, now); err != nil {
		return nil, "", err
	}

	cert, err := authp.ReadServerCertificate()
	// FIXME[P2]: check if ns matches
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}

		var srvEnv action.Environment
		srvEnv = *env
		srvEnv.ProfileName = authprofile.ProfileName
		issueCfg := issue.Config{
			Subject: &dname.Config{
				CommonName: "kmgm server",
			},
			Names:    ns,
			KeyUsage: keyusage.KeyUsageTLSServer.Clone(),
			Validity: validityperiod.ValidityPeriod{Days: 820},
			KeyType:  wcrypto.ServerKeyType,

			NoIssueDBEntry: true,
		}
		certDer, err := issue.Run(&srvEnv, pub, &issueCfg)
		if err != nil {
			return nil, "", fmt.Errorf("Failed to issue server cert: %w", err)
		}
		cert, err = x509.ParseCertificate(certDer)
		if err != nil {
			return nil, "", fmt.Errorf("Failed to parse server cert: %w", err)
		}

		if err := authp.WriteServerCertificate(cert); err != nil {
			return nil, "", err
		}
	}

	now = time.Now()
	if err := wcrypto.VerifyServerCert(cert, cacert, now); err != nil {
		// FIXME[P2]: try reissueing cert once
		return nil, "", err
	}

	pub, ok := cert.PublicKey.(crypto.PublicKey)
	if !ok {
		return nil, "", errors.New("Failed to extract cert's public key as crypto.PublicKey")
	}
	tlscert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw, cacert.Raw},
		PrivateKey:  priv,
	}
	pubkeyhash, err := wcrypto.PubKeyPinString(pub)
	if err != nil {
		return nil, "", err
	}
	return tlscert, pubkeyhash, nil
}
