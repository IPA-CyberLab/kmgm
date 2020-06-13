package certshandler

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/httperr"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
)

type Handler struct {
	env *action.Environment
}

func New(env *action.Environment) http.Handler {
	return &Handler{env}
}

func serveCertificate(w http.ResponseWriter, cert *x509.Certificate, filename string) error {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.QueryEscape(filename))
	w.Header().Set("Content-Type", "application/x-pem-file")
	certPem := pemparser.MarshalCertificateDer(cert.Raw)
	if _, err := w.Write(certPem); err != nil {
		return fmt.Errorf("Failed to output PEM: %w", err)
	}
	return nil
}

func (h *Handler) serveHTTPIfPossible(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return httperr.ErrorWithStatusCode{
			StatusCode: http.StatusBadRequest,
			Err:        errors.New("Unsupported method")}
	}

	env := h.env.Clone()
	slog := env.Logger.Sugar()

	var queryStr string

	args := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch len(args) {
	case 1:
		queryStr = args[0]
	case 2:
		env.ProfileName = args[0]
		queryStr = args[1]
	default:
		return httperr.ErrorWithStatusCode{
			StatusCode: http.StatusNotFound,
			Err:        errors.New("bad path")}
	}
	queryStr = strings.TrimSuffix(queryStr, ".pem")

	slog.Debugf("certshandler GET profile: %s, queryStr: %s", env.ProfileName, queryStr)

	profile, err := env.Profile()
	if err != nil {
		return err
	}

	switch queryStr {
	case "":
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("/issue/[profileName]/[query].pem\n"))
		return nil
	case "cacert":
		cacert, err := profile.ReadCACertificate()
		if err != nil {
			return fmt.Errorf("Failed to query cacert: %w", err)
		}

		return serveCertificate(w, cacert, "cacert.pem")
	}

	db, err := issuedb.New(profile.IssueDBPath())
	if err != nil {
		return err
	}

	db.Query(123)

	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog := h.env.Logger.Sugar()

	if err := h.serveHTTPIfPossible(w, r); err != nil {
		slog.Warnw("Failed to process request", "err", err)
		http.Error(w, fmt.Sprintf("Failed to process request: %v", err), httperr.StatusCodeFromError(err))
	}
}
