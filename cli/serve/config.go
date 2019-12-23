package serve

import (
	"time"

	"github.com/IPA-CyberLab/kmgm/san"
)

type Config struct {
	ListenAddr string `flags:"listen-addr,server listen host:addr (:34680)"`

	Names san.Names `flags:"subject-alt-name,set subjectAltNames to use on server certificate,san"`

	IssueHttp int `flags:"issue-http,enable certificate issue via HTTP API"`

	AutoShutdown time.Duration `flags:"auto-shutdown,auto shutdown server after specified time"`

	// Enable node bootstrapping with the given auth provider.
	Bootstrap TokenAuthProvider
}

func DefaultConfig() (*Config, error) {
	cfg := &Config{
		ListenAddr: ":34680",
		IssueHttp:  0,
	}
	return cfg, nil
}
