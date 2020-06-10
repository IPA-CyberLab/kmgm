package issue

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/consts"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

const promSubsystem = "issue"

var (
	startedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: consts.PrometheusNamespace,
			Subsystem: promSubsystem,
			Name:      "issue_started_total",
		},
		[]string{"profile"},
	)
	handledCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: consts.PrometheusNamespace,
			Subsystem: promSubsystem,
			Name:      "issue_handled_total",
		},
		[]string{"profile", "error"},
	)
)

func createCertificate(env *action.Environment, now time.Time, pub crypto.PublicKey, cfg *Config, cacert *x509.Certificate, capriv crypto.PrivateKey, serial int64) ([]byte, error) {
	slog := env.Logger.Sugar()

	start := time.Now()
	slog.Info("Generating certificate...")

	kt, err := wcrypto.KeyTypeOfPub(pub)
	if err != nil {
		return nil, err
	}
	if err := cfg.KeyType.CompatibleWith(kt); err != nil {
		return nil, err
	}

	t := &x509.Certificate{
		// AuthorityKeyId is automatically set by x509.CreateCertificate
		BasicConstraintsValid: true,

		// Subject Alternate Name Values
		DNSNames:    cfg.Names.DNSNames,
		IPAddresses: cfg.Names.IPAddrs,
		// - EmailAddresses
		// - URIs

		// Name Constraints: not applicable to endpoint certs
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

		IsCA:        false,
		KeyUsage:    cfg.KeyUsage.KeyUsage,
		ExtKeyUsage: cfg.KeyUsage.ExtKeyUsages,
		// UnknownExtKeyUsage: []asn1.ObjectIdentifier{},

		// ExtraExtensions: []pkix.Extension,

		// pathlen not applicable to endpoint certs
		// MaxPathLen:     0,
		// MaxPathLenZero: true,

		NotAfter:  cfg.Validity.GetNotAfter(now).UTC(),
		NotBefore: now.Add(-consts.NodesOutOfSyncThreshold).UTC(),

		SerialNumber: new(big.Int).SetInt64(serial),

		// SignatureAlgorithm will be auto-specified by x509 package

		Subject: cfg.Subject.ToPkixName(),

		// FIXME[P4]: CRLDistributionPoints:
	}
	certDer, err := x509.CreateCertificate(env.Randr, t, cacert, pub, capriv)
	if err != nil {
		return nil, fmt.Errorf("Create cert failed: %w", err)
	}

	slog.Infow("Generating certificate... Done.", "took", time.Now().Sub(start))
	return certDer, nil
}

// FIXME[P2]: make concurrent safe
func Run(env *action.Environment, pub crypto.PublicKey, cfg *Config) ([]byte, error) {
	now := env.NowImpl()

	startedCounter.WithLabelValues(env.ProfileName).Inc()

	if err := cfg.Verify(now); err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "VerifyFailed").Inc()
		return nil, err
	}

	profile, err := env.Profile()
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "GetProfileFailed").Inc()
		return nil, err
	}

	db, err := issuedb.New(env.Randr, profile.IssueDBPath())
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "OpenIssueDBFailed").Inc()
		return nil, err
	}

	capriv, err := profile.ReadCAPrivateKey()
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "ReadPrivateKeyFailed").Inc()
		return nil, err
	}

	cacert, err := profile.ReadCACertificate()
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "ReadCACertificateFailed").Inc()
		return nil, err
	}

	slog := env.Logger.Sugar()

	if err := wcrypto.VerifyCACertAndKey(capriv, cacert, now); err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "VerifyCACertAndKeyFailed").Inc()
		return nil, err
	}

	var serial int64
	if cfg.NoIssueDBEntry {
		serial = issuedb.RandInt63(env.Randr)
	} else {
		serial, err = db.AllocateSerialNumber()
		if err != nil {
			handledCounter.WithLabelValues(env.ProfileName, "AllocateSerialNumberFailed").Inc()
			return nil, err
		}
		slog.Infof("Allocated sn: %v", serial)
	}

	certDer, err := createCertificate(env, now, pub, cfg, cacert, capriv, serial)
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "CreateCertificateFailed").Inc()
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  pemparser.CertificatePemType,
		Bytes: certDer,
	})
	if !cfg.NoIssueDBEntry {
		if err := db.IssueCertificate(serial, string(certPem)); err != nil {
			handledCounter.WithLabelValues(env.ProfileName, "DBIssueCertificateFailed").Inc()
			return nil, err
		}
	}

	handledCounter.WithLabelValues(env.ProfileName, "Success").Inc()
	return certDer, nil
}
