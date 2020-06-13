package exporter

import (
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

	entriesTotalDesc *prometheus.Desc
}

func NewCollector(storage *storage.Storage, logger *zap.Logger) prometheus.Collector {
	return &collector{
		storage: storage,
		logger:  logger,

		entriesTotalDesc: prometheus.NewDesc(
			prometheus.BuildFQName(
				consts.PrometheusNamespace,
				promSubsystemDB,
				"entries_total",
			),
			"Number of entries in the CA issue db",
			[]string{"profile", "status"},
			nil,
		),
	}
}

var _ = prometheus.Collector(&collector{})

// Describe returns all descriptions of the collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.entriesTotalDesc
}

// Collect returns the current state of all metrics of the collector.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	slog := c.logger.Sugar()

	ps, err := c.storage.Profiles()
	if err != nil {
		slog.Warnf("collector: storage.Profiles() failed: %v", err)
	}

	for _, p := range ps {
		// FIXME[P1] export profile status as well
		profileName := p.Name()

		db, err := issuedb.New(p.IssueDBPath())
		if err != nil {
			slog.Warnf("Failed to open issuedb %q: %v", p.IssueDBPath(), err)
			continue
		}

		entries, err := db.Entries()
		if err != nil {
			slog.Warnf("collector: storage.Profiles() failed: %v", err)
		}

		m := make(map[issuedb.State]int)
		for _, e := range entries {
			m[e.State]++
		}
		for state, count := range m {
			ch <- prometheus.MustNewConstMetric(c.entriesTotalDesc, prometheus.GaugeValue, float64(count), profileName, state.String())
		}
	}
}
