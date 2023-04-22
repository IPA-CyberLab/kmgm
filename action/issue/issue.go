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
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

const promSubsystem = "issue"

var (
	startedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: consts.PrometheusNamespace,
			Subsystem: promSubsystem,
			Name:      "started_total",
		},
		[]string{"profile"},
	)
	handledCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: consts.PrometheusNamespace,
			Subsystem: promSubsystem,
			Name:      "handled_total",
		},
		[]string{"profile", "error"},
	)

	durationSecondsSummary = promauto.NewSummary(
		prometheus.SummaryOpts{
			Namespace:  consts.PrometheusNamespace,
			Subsystem:  promSubsystem,
			Name:       "duration_seconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
	)
)

func createCertificate(env *action.Environment, now time.Time, pub crypto.PublicKey, cfg *Config, cacert *x509.Certificate, capriv crypto.PrivateKey, serial int64) ([]byte, error) {
	pubkeyhash, err := wcrypto.PubKeyPinString(pub)
	if err != nil {
		pubkeyhash = fmt.Sprintf("Error: %v", err)
	}
	capubkeyhash, err := wcrypto.PubKeyPinString(cacert.PublicKey)
	if err != nil {
		capubkeyhash = fmt.Sprintf("Error: %v", err)
	}

	slog := env.Logger.Sugar().With(
		"profile", env.ProfileName,
		"subject", cfg.Subject.ToPkixName().String(),
		"dnsnames", cfg.Names.DNSNames,
		"ipaddrs", cfg.Names.IPAddrs,
		"pubkeyhash", pubkeyhash,
		"cacpubkeyhash", capubkeyhash,
		"serial", serial,
		"validity", cfg.Validity,
	)

	start := time.Now()
	slog.Info("Generating leaf certificate...")

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

	slog.Infow("Generating leaf certificate... Done.", "took", time.Now().Sub(start))
	return certDer, nil
}

// FIXME[P2]: make concurrent safe
func Run(env *action.Environment, pub crypto.PublicKey, cfg *Config) ([]byte, error) {
	start := env.NowImpl()

	startedCounter.WithLabelValues(env.ProfileName).Inc()

	if err := cfg.Verify(start); err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "VerifyFailed").Inc()
		return nil, err
	}

	profile, err := env.Profile()
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "GetProfileFailed").Inc()
		return nil, fmt.Errorf("Failed to acquire profile: %w", err)
	}
	if st := profile.Status(start); st.Code != storage.ValidCA {
		return nil, fmt.Errorf("Can't issue certificate from CA profile %q: %w", env.ProfileName, st)
	}

	db, err := issuedb.New(profile.IssueDBPath())
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "OpenIssueDBFailed").Inc()
		return nil, fmt.Errorf("Failed to open issuedb: %w", err)
	}

	capriv, err := profile.ReadCAPrivateKey()
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "ReadPrivateKeyFailed").Inc()
		return nil, fmt.Errorf("Failed to read CA private key: %w", err)
	}

	cacert, err := profile.ReadCACertificate()
	if err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "ReadCACertificateFailed").Inc()
		return nil, fmt.Errorf("Failed to read CA certificate: %w", err)
	}

	slog := env.Logger.Sugar()

	if err := wcrypto.VerifyCACertAndKey(capriv, cacert, start); err != nil {
		handledCounter.WithLabelValues(env.ProfileName, "VerifyCACertAndKeyFailed").Inc()
		return nil, fmt.Errorf("Failed to verify CA certkey pair: %w", err)
	}

	var serial int64
	if cfg.NoIssueDBEntry {
		serial = issuedb.RandInt63(env.Randr)
	} else {
		serial, err = db.AllocateSerialNumber(env.Randr)
		if err != nil {
			handledCounter.WithLabelValues(env.ProfileName, "AllocateSerialNumberFailed").Inc()
			return nil, fmt.Errorf("Failed to allocate s/n: %w", err)
		}
		slog.Infof("Allocated sn: %v", serial)
	}

	certDer, err := createCertificate(env, start, pub, cfg, cacert, capriv, serial)
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

	durationSecondsSummary.Observe(env.NowImpl().Sub(start).Seconds())
	handledCounter.WithLabelValues(env.ProfileName, "Success").Inc()
	return certDer, nil
}
