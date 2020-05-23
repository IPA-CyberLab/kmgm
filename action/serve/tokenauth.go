package serve

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

type TokenAuthProvider interface {
	Authenticate(token string, now time.Time) error
	LogHelpMessage(listenAddr, pubkeyhash string)
}

type FixedTokenAuthProvider struct {
	Token    string
	NotAfter time.Time
	Logger   *zap.Logger
}

var _ = TokenAuthProvider(&FixedTokenAuthProvider{})

var ErrBadToken = errors.New("Bad token.")
var ErrTokenExpired = errors.New("Token expired.")

func (ta *FixedTokenAuthProvider) Authenticate(t string, now time.Time) error {
	slog := ta.Logger.Sugar()

	if t != ta.Token {
		slog.Infof("Bad token %q provided.")
		return ErrBadToken
	}
	if now.After(ta.NotAfter) {
		slog.Infof("Token provided has expired. It was valid until %v.", ta.NotAfter)
		return ErrTokenExpired
	}
	slog.Debugf("Token auth succeeded.")
	return nil
}

func (ta *FixedTokenAuthProvider) LogHelpMessage(listenAddr, pubkeyhash string) {
	slog := ta.Logger.Sugar()

	// FIXME[P3]: make NotAfter configurable.
	slog.Infof("Node bootstrap enabled for 15 minutes using token: %s", ta.Token)
	slog.Infof("For your convenience, bootstrap command-line to be executed on your clients would look like: kmgm client --server %s --pinnedpubkey %s --token %s bootstrap", FormatListenAddr(listenAddr), pubkeyhash, ta.Token)
}

type tokenFileAuthProvider struct {
	path   string
	logger *zap.Logger
}

var _ = TokenAuthProvider(&tokenFileAuthProvider{})

func NewTokenFileAuthProvider(path string, logger *zap.Logger) (TokenAuthProvider, error) {
	slog := logger.Sugar()

	apath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	ta := &tokenFileAuthProvider{path: apath, logger: logger}
	slog.Debugf("Initialized tokenFileAuthProvider{%q}", apath)

	if _, err := ioutil.ReadFile(ta.path); err != nil {
		slog.Infof("Failed to read token file: %v", err)
	}

	return ta, nil
}

func (ta *tokenFileAuthProvider) Authenticate(t string, now time.Time) error {
	slog := ta.logger.Sugar()

	st, err := os.Stat(ta.path)
	if err != nil {
		slog.Warnf("Failed to stat token file: %v", err)
		return ErrBadToken
	}
	modt := st.ModTime()
	// FIXME[P3]: make NotAfter configurable.
	if now.Sub(modt) > 15*time.Minute {
		slog.Warnf("The token file is too old. It must be modified w/in 15 min to be valid")
		return ErrBadToken
	}

	bs, err := ioutil.ReadFile(ta.path)
	if err != nil {
		slog.Warnf("Failed to read token file: %v", err)
		return ErrBadToken
	}
	token := strings.TrimSpace(string(bs))
	if t != token {
		slog.Infof("Expected token %q, but got %q.", token, t)
		return ErrBadToken
	}

	return nil
}

func (ta *tokenFileAuthProvider) LogHelpMessage(listenAddr, pubkeyhash string) {
	slog := ta.logger.Sugar()

	slog.Infof("Node bootstrap enabled. Token is read from file %q.", ta.path)
	slog.Infof("For your convenience, bootstrap command-line to be executed on your clients would look like: kmgm client --server %s --pinnedpubkey %s --token [token] bootstrap", FormatListenAddr(listenAddr), pubkeyhash)
}

var ipDocker = net.IPv4(172, 17, 0, 1)

// FormatListenAddr takes a hostport str, and appends an interface ip addr as
// a host if the original host was empty or 0.0.0.0.
func FormatListenAddr(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		log.Panicf("Failed to net.SplitHostPort(%q): %v", listenAddr, err)
	}
	if host == "" || host == "0.0.0.0" {
		if addrs, err := net.InterfaceAddrs(); err == nil {
			type candidate struct {
				Host  string
				Score int
			}
			cs := make([]candidate, 0, len(addrs))
			for _, addr := range addrs {
				if ipaddr, ok := addr.(*net.IPNet); ok {
					ip := ipaddr.IP
					c := candidate{Host: ip.String(), Score: 100}
					if ip4 := ip.To4(); len(ip4) == net.IPv4len {
						c.Score += 50
					}
					if ip.IsLoopback() {
						c.Score -= 10
					}
					if ip.Equal(ipDocker) {
						c.Score -= 20
					}
					if ip.IsLinkLocalUnicast() {
						c.Score -= 30
					}
					cs = append(cs, c)
				}
			}

			// sort by .Score desc
			sort.Slice(cs, func(i, j int) bool { return cs[i].Score > cs[j].Score })
			host = cs[0].Host
		}
	}

	return net.JoinHostPort(host, port)
}
