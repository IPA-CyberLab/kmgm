package httpzaplog

import (
	"net/http"

	"go.uber.org/zap"
)

type Handler struct {
	Upstream http.Handler
	*zap.Logger
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var remoteCN string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peerCert := r.TLS.PeerCertificates[0]
		remoteCN = peerCert.Subject.CommonName
	}

	h.Logger.Info("ServeHTTP",
		zap.String("url", r.URL.String()),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("remote_common_name", remoteCN),
	)

	h.Upstream.ServeHTTP(w, r)
}
