package exporter

import (
	"crypto/x509"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/IPA-CyberLab/kmgm/consts"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
)

const promSubsystemDB = "issuedb"

type collector struct {
	storage *storage.Storage
	logger  *zap.Logger

	caStatusDesc        *prometheus.Desc
	entriesTotalDesc    *prometheus.Desc
	certExpiresDaysDesc *prometheus.Desc
}

func NewCollector(storage *storage.Storage, logger *zap.Logger) prometheus.Collector {
	return &collector{
		storage: storage,
		logger:  logger,

		caStatusDesc: prometheus.NewDesc(
			prometheus.BuildFQName(
				consts.PrometheusNamespace,
				"ca",
				"status",
			),
			"CA status",
			[]string{"profile", "status"},
			nil,
		),
		entriesTotalDesc: prometheus.NewDesc(
			prometheus.BuildFQName(
				consts.PrometheusNamespace,
				promSubsystemDB,
				"entries_total",
			),
			"Number of entries in the CA issue db with the status",
			[]string{"profile", "status"},
			nil,
		),
		certExpiresDaysDesc: prometheus.NewDesc(
			prometheus.BuildFQName(
				consts.PrometheusNamespace,
				promSubsystemDB,
				"expires_days",
			),
			"The certificate expires after given days",
			[]string{"profile", "serialNumber", "subject"},
			nil,
		),
	}
}

var _ = prometheus.Collector(&collector{})

// Describe returns all descriptions of the collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.caStatusDesc
	ch <- c.entriesTotalDesc
	ch <- c.certExpiresDaysDesc
}

// Collect returns the current state of all metrics of the collector.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	slog := c.logger.Sugar()
	now := time.Now()

	ps, err := c.storage.Profiles()
	if err != nil {
		slog.Warnf("collector: storage.Profiles() failed: %v", err)
		return
	}

	for _, p := range ps {
		profileName := p.Name()

		st := p.Status(now)
		for code := storage.CAStatusCode(0); code < storage.MaxCAStatusCode+1; code++ {
			eq := float64(0)
			if code == st.Code {
				eq = 1
			}
			ch <- prometheus.MustNewConstMetric(c.caStatusDesc, prometheus.GaugeValue, eq, profileName, code.String())
		}

		db, err := issuedb.New(p.IssueDBPath())
		if err != nil {
			slog.Warnf("Failed to open issuedb %q: %v", p.IssueDBPath(), err)
			continue
		}

		entries, err := db.Entries()
		if err != nil {
			slog.Warnf("collector: storage.Profiles() failed: %v", err)
		}

		stateCount := make(map[issuedb.State]int)
		farthestNotAfter := make(map[string]*x509.Certificate)
		for _, e := range entries {
			stateCount[e.State]++

			if e.State != issuedb.ActiveCertificate {
				continue
			}
			cert, err := e.ParseCertificate()
			if err != nil {
				continue
			}

			subj := cert.Subject.String()

			farthest, ok := farthestNotAfter[subj]
			if !ok || farthest.NotAfter.Before(cert.NotAfter) {
				farthestNotAfter[subj] = cert
			}
		}
		for state := issuedb.State(0); state < issuedb.MaxState+1; state++ {
			count := stateCount[state]
			ch <- prometheus.MustNewConstMetric(c.entriesTotalDesc, prometheus.GaugeValue, float64(count), profileName, state.String())
		}
		for _, cert := range farthestNotAfter {
			expiresDays := cert.NotAfter.Sub(now).Hours() / 24
			ch <- prometheus.MustNewConstMetric(c.certExpiresDaysDesc, prometheus.GaugeValue, expiresDays, profileName, cert.SerialNumber.String(), cert.Subject.String())
		}
	}
}
