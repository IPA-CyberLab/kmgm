package serve

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
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
	// FIXME[P2]: pick random listenaddr. otherwise this will present "--server :34680" which is useless
	slog.Infof("For your convenience, bootstrap command-line to be executed on your clients would look like: kmgm client --server %s --pinnedpubkey %s --token %s bootstrap", listenAddr, pubkeyhash, ta.Token)
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
	// FIXME[P2]: pick random listenaddr. otherwise this will present "--server :34680" which is useless
	slog.Infof("For your convenience, bootstrap command-line to be executed on your clients would look like: kmgm client --server %s --pinnedpubkey %s --token [token] bootstrap", listenAddr, pubkeyhash)
}
