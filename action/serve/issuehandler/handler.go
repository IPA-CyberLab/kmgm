package issuehandler

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/httperr"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

type Handler struct {
	env *action.Environment

	token            string
	allowedCountLeft int
	mu               sync.Mutex
}

func New(env *action.Environment, count int) (*Handler, error) {
	token, err := wcrypto.GenBase64Token(env.Randr, env.Logger)
	if err != nil {
		return nil, err
	}

	return &Handler{
		env:              env,
		token:            token,
		allowedCountLeft: count,
	}, nil
}

func getDefaultServerAddrString() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipaddr, ok := addr.(*net.IPNet); ok {
			ip := ipaddr.IP
			if ip.IsLoopback() {
				continue
			}

			return ip.String(), nil
		}
	}

	return "", errors.New("Could not find a server ip address.")
}

func (h *Handler) CurlString(listenAddr, pubkeyhash string) (string, error) {
	hostport := listenAddr
	listenHost, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("Failed to parse listenAddr %q: %w", listenAddr, err)
	}
	if listenHost == "" {
		addrstr, err := getDefaultServerAddrString()
		if err != nil {
			return "", fmt.Errorf("Failed to get default server host: %w", err)
		}
		hostport = addrstr + hostport
	}

	return fmt.Sprintf("curl -kOJ --pinnedpubkey sha256//%s \"https://%s/issue?token=%s&cn=`hostname`&san=`hostname -f`&san_remoteip\"",
		pubkeyhash,
		hostport,
		h.token,
	), nil
}

// Avoid client tar warn about future timestamp.
const SkewWorkaround = -5 * time.Second

func writeKeyCertTar(w io.Writer, privbs, certbs []byte) error {
	modt := time.Now().Add(SkewWorkaround)

	tw := tar.NewWriter(w)

	if err := tw.WriteHeader(&tar.Header{
		Name:    "key.pem",
		Mode:    0400,
		Size:    int64(len(privbs)),
		ModTime: modt,
	}); err != nil {
		return err
	}
	if _, err := tw.Write(privbs); err != nil {
		return err
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:    "cert.pem",
		Mode:    0644,
		Size:    int64(len(certbs)),
		ModTime: modt,
	}); err != nil {
		return err
	}
	if _, err := tw.Write(certbs); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return nil
}

func (h *Handler) serveHTTPIfPossible(w http.ResponseWriter, r *http.Request) error {
	slog := h.env.Logger.Sugar()

	q := r.URL.Query()

	// FIXME[P3]: allow Authorization header
	token := q.Get("token")
	if token != h.token {
		return httperr.ErrorWithStatusCode{http.StatusUnauthorized, errors.New("Invalid token.")}
	}

	profile, err := h.env.Storage.Profile(storage.DefaultProfileName)
	if err != nil {
		return err
	}

	caSubject, err := profile.ReadCASubject()
	if err != nil {
		return err
	}

	subject, err := dname.DefaultConfig("", caSubject)
	if err != nil {
		return err
	}

	ktype := wcrypto.KeyRSA4096
	if s := q.Get("ktype"); s != "" {
		ktype, err = wcrypto.KeyTypeFromString(s)
		if err != nil {
			return httperr.ErrorWithStatusCode{http.StatusBadRequest, err}
		}
	}

	commonName := q.Get("cn")
	if commonName == "" {
		return httperr.ErrorWithStatusCode{http.StatusBadRequest, errors.New("param \"cn\" is not specified.")}
	}
	subject.CommonName = commonName

	var ns san.Names
	if err := ns.Add(commonName); err != nil {
		slog.Infof("Failed to add commonName %q as subjectAltName: %w", err)
	}

	for _, e := range q["san"] {
		if err := ns.Add(e); err != nil {
			return httperr.ErrorWithStatusCode{http.StatusBadRequest, fmt.Errorf("Failed to parse subjectAltName entry %q: %w", e, err)}
		}
	}

	if _, set := q["san_remoteip"]; set {
		raddrWithPort := r.RemoteAddr
		raddr, _, err := net.SplitHostPort(raddrWithPort)
		if err != nil {
			return httperr.ErrorWithStatusCode{http.StatusBadRequest, fmt.Errorf("Failed to parse remoteip %q: %w", raddrWithPort, err)}
		}
		if err := ns.Add(raddr); err != nil {
			return httperr.ErrorWithStatusCode{http.StatusBadRequest, fmt.Errorf("Failed to add remoteip %q as subjectAltName: %w", raddr, err)}
		}
	}

	days := uint(860)
	if s, set := q["days"]; set {
		n, err := strconv.ParseUint(s[0], 10, 32)
		if err != nil {
			return httperr.ErrorWithStatusCode{http.StatusBadRequest, fmt.Errorf("Failed to parse days %q: %w", s[0], err)}
		}
		days = uint(n)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.allowedCountLeft <= 0 {
		return httperr.ErrorWithStatusCode{http.StatusTooManyRequests, errors.New("/issue was invoked for more than its allowed count.")}
	}
	h.allowedCountLeft -= 1

	priv, err := wcrypto.GenerateKey(h.env.Randr, ktype, "", h.env.Logger)
	if err != nil {
		return err
	}
	privPem, err := pemparser.MarshalPrivateKey(priv)
	if err != nil {
		return err
	}

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		return err
	}

	cfg := issue.Config{
		Subject:  subject,
		Names:    ns,
		KeyUsage: keyusage.KeyUsageTLSClientServer.Clone(),
		Validity: issue.ValidityPeriod{Days: days},
	}

	certDer, err := issue.Run(h.env, pub, &cfg)
	if err != nil {
		return err
	}
	certPem := pemparser.MarshalCertificateDer(certDer)

	w.Header().Set("Content-Disposition", "attachment; filename=\"keycert.tar\"")
	w.Header().Set("Content-Type", "application/tar")
	if err := writeKeyCertTar(w, privPem, certPem); err != nil {
		return err
	}

	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog := h.env.Logger.Sugar()

	if err := h.serveHTTPIfPossible(w, r); err != nil {
		slog.Warnw("Failed to process request", "err", err)
		http.Error(w, fmt.Sprintf("Failed to process request: %v", err), httperr.StatusCodeFromError(err))
	}
}
