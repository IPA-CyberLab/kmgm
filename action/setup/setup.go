package setup

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	// zx509 "github.com/zmap/zcrypto/x509"
	// "github.com/zmap/zlint"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/consts"
	"github.com/IPA-CyberLab/kmgm/frontend/validate"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

func createCertificate(env *action.Environment, cfg *Config, priv crypto.PrivateKey) ([]byte, error) {
	slog := env.Logger.Sugar()

	start := time.Now()
	slog.Infow("Generating certificate...")

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		return nil, err
	}

	kt, err := wcrypto.KeyTypeOfPub(pub)
	if err != nil {
		return nil, err
	}
	if err := cfg.KeyType.CompatibleWith(kt); err != nil {
		return nil, err
	}

	ski, err := wcrypto.SubjectKeyIdFromPubkey(pub)
	if err != nil {
		return nil, err
	}

	now := env.NowImpl()
	t := &x509.Certificate{
		// AuthorityKeyId meaningless for self-signed
		BasicConstraintsValid: true,

		// Subject Alternate Name Values should be empty for CA:
		// - DNSNames
		// - EmailAddresses
		// - IPAddresses
		// - URIs

		// FIXME[P2]: Name Constraints:
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.10
		// - ExcludedDNSDomains
		// - ExcludedEmailAddresses
		// - ExcludedIPRanges
		// - ExcludedURIDomains
		// - PermittedDNSDomains
		// - PermittedDNSDomainsCritical
		// - PermittedEmailAddresses
		// - PermittedIPRanges
		// - PermittedURIDomains

		// https://tools.ietf.org/html/rfc5280#section-4.2.2.1
		// OCSPServer: []string{},
		// IssuingCertificateURL: []string{},

		// https://tools.ietf.org/html/rfc3647
		// PolicyIdentifiers: []asn1.ObjectIdentifier{},

		IsCA:     true,
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		// ExtKeyUsage: []ExtKeyUsage{},
		// UnknownExtKeyUsage: []asn1.ObjectIdentifier{},

		// ExtraExtensions: []pkix.Extension,

		// pathlen of 0 : Sign end-user certs only
		MaxPathLen:     0,
		MaxPathLenZero: true,

		NotAfter:  cfg.Validity.GetNotAfter(now).UTC(),
		NotBefore: now.Add(-consts.NodesOutOfSyncThreshold).UTC(),

		// FIXME[P2]: https://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers
		SerialNumber: new(big.Int).SetInt64(1),

		// SignatureAlgorithm will be auto-specified by x509 package

		Subject: cfg.Subject.ToPkixName(),

		// https://security.stackexchange.com/questions/200295/the-difference-between-subject-key-identifier-and-sha1fingerprint-in-x509-certif
		// https://security.stackexchange.com/questions/27797/what-damage-could-be-done-if-a-malicious-certificate-had-an-identical-subject-k?rq=1
		SubjectKeyId: ski,

		// CRLDistributionPoints: FIXME
	}
	parent := t // self signed cert

	certDer, err := x509.CreateCertificate(env.Randr, t, parent, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("Create self-signed CA cert failed: %w", err)
	}
	slog.Infow("Generating certificate... Done.", "took", time.Now().Sub(start))
	return certDer, nil
}

func Run(env *action.Environment, cfg *Config) error {
	slog := env.Logger.Sugar()

	profile, err := env.Profile()
	if err != nil {
		return err
	}
	idb, err := issuedb.New(env.Randr, profile.IssueDBPath())
	if err != nil {
		return err
	}

	if err := validate.MkdirAndCheckWritable(profile.CAPrivateKeyPath()); err != nil {
		return err
	}
	if err := validate.MkdirAndCheckWritable(profile.CACertPath()); err != nil {
		return err
	}
	if err := idb.Initialize(); err != nil {
		return err
	}

	priv, err := wcrypto.GenerateKey(env.Randr, cfg.KeyType, "CA", env.Logger)
	if err != nil {
		return err
	}
	if err := profile.WriteCAPrivateKey(priv); err != nil {
		return err
	}
	slog.Infof("The CA private key saved to file: %s", profile.CAPrivateKeyPath())

	certDer, err := createCertificate(env, cfg, priv)
	if err != nil {
		return err
	}

	/*
		cert, _ := zx509.ParseCertificate(certDer)
		lintrs := zlint.LintCertificate(cert)
		j, _ := json.Marshal(lintrs.Results)
		var buf bytes.Buffer
		json.Indent(&buf, j, "", " ")
		log.Printf("%s", buf.String())
	*/

	if err := profile.WriteCACertificateDer(certDer); err != nil {
		return err
	}
	slog.Infof("The CA certificate saved to file: %s", profile.CACertPath())

	return nil
}
