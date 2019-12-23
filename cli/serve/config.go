package serve

import (
	"time"

	"github.com/IPA-CyberLab/kmgm/san"
)

type Config struct {
	ListenAddr string

	// SubjectAltNames to use on server certificate
	Names san.Names

	// Enable /issue endpoint for N times.
	IssueHttp int

	// Enable node bootstrapping with the given auth provider.
	Bootstrap TokenAuthProvider

	// Auto shutdown the server after specified time if specified.
	AutoShutdown time.Duration
}

func DefaultConfig() (*Config, error) {
	cfg := &Config{
		ListenAddr: ":34680",
		IssueHttp:  0,
	}
	return cfg, nil
}
