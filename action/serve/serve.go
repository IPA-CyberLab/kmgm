package serve

// FIXME[P4]: may be move this to github.com/IPA-CyberLab/kmgm/srv ?

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/serve/authprofile"
	"github.com/IPA-CyberLab/kmgm/action/serve/certificateservice"
	"github.com/IPA-CyberLab/kmgm/action/serve/certshandler"
	"github.com/IPA-CyberLab/kmgm/action/serve/httpzaplog"
	"github.com/IPA-CyberLab/kmgm/action/serve/issuehandler"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/remote/user"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/storage"
)

func grpcHttpMux(grpcServer *grpc.Server, httpHandler http.Handler) http.Handler {
	// based on code from:
	// https://github.com/philips/grpc-gateway-example

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}

const BearerPrefix = "bearer "

func generateAuthFunc(authp *storage.Profile, tauth TokenAuthProvider) (grpc_auth.AuthFunc, error) {
	cacert, err := authp.ReadCACertificate()
	if err != nil {
		return nil, err
	}

	cp := x509.NewCertPool()
	cp.AddCert(cacert)

	authfunc := func(ctx context.Context) (context.Context, error) {
		u := user.Anonymous

		if p, ok := peer.FromContext(ctx); ok {
			if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok {
				pcerts := ti.State.PeerCertificates
				if len(pcerts) > 0 {
					pc := pcerts[0]
					// FIXME: move this to wcrypto/cert
					if _, err := pc.Verify(x509.VerifyOptions{
						Roots:     cp,
						KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					}); err != nil {
						return nil, grpc.Errorf(codes.Unauthenticated, "Failed to verify client cert: %v", err)
					}

					u = user.ClientCert(pc.Subject.CommonName)
				}
			}
		}
		if u.Type == pb.AuthenticationType_ANONYMOUS {
			authHeader := metautils.ExtractIncoming(ctx).Get("authorization")

			if authHeader != "" {
				if len(authHeader) < len(BearerPrefix) ||
					!strings.EqualFold(authHeader[:len(BearerPrefix)], BearerPrefix) {
					return nil, grpc.Errorf(codes.Unauthenticated, "Bad scheme")
				}
				token := authHeader[len(BearerPrefix):]

				if token == "" {
					return nil, grpc.Errorf(codes.Unauthenticated, "Empty token")
				}
				if tauth == nil {
					return nil, grpc.Errorf(codes.Unauthenticated, "Token auth disabled")
				}
				if err := tauth.Authenticate(token, time.Now()); err != nil {
					return nil, grpc.Errorf(codes.Unauthenticated, "%v", err)
				}
				u = user.BootstrapToken
			}
		}

		grpc_ctxtags.Extract(ctx).Set("auth.sub", u.Name)
		ctx = user.NewContext(ctx, u)
		return ctx, nil
	}
	return authfunc, nil
}

type Server struct {
	Shutdown func(ctx context.Context) error
}

func StartServer(ctx context.Context, env *action.Environment, cfg *Config) (*Server, error) {
	slog := env.Logger.Sugar()

	if cfg.Names.Empty() {
		cfg.Names = san.ForThisHost(cfg.ListenAddr)
	}

	authp, err := authprofile.Ensure(env)
	if err != nil {
		return nil, err
	}

	tlscert, pubkeyhash, err := ensureServerCert(env, authp, cfg.Names)
	if err != nil {
		return nil, err
	}

	authfunc, err := generateAuthFunc(authp, cfg.Bootstrap)
	if err != nil {
		return nil, err
	}

	listenAddr := cfg.ListenAddr
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var soptErr error
			if err := c.Control(func(fd uintptr) {
				soptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			if soptErr != nil {
				return soptErr
			}
			return nil
		},
	}
	lis, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("Failed to listen to %q: %w", listenAddr, err)
	}

	slog.Infof("Started listening to %q. My public key hash is %s.", listenAddr, pubkeyhash)
	if cfg.Bootstrap != nil {
		cfg.Bootstrap.LogHelpMessage(listenAddr, pubkeyhash)
	}

	uics := []grpc.UnaryServerInterceptor{
		grpc_ctxtags.UnaryServerInterceptor(
			grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.TagBasedRequestFieldExtractor("log_fields")),
		),
		grpc_auth.UnaryServerInterceptor(authfunc),
		grpc_zap.UnaryServerInterceptor(env.Logger),
		grpc_prometheus.UnaryServerInterceptor,
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(tlscert)),
		grpc_middleware.WithUnaryServerChain(uics...),
	)
	pb.RegisterHelloServiceServer(grpcServer, &helloService{})
	pb.RegisterVersionServiceServer(grpcServer, &versionService{})
	certsvc, err := certificateservice.New(env)
	if err != nil {
		return nil, err
	}
	pb.RegisterCertificateServiceServer(grpcServer, certsvc)
	reflection.Register(grpcServer)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})
	mux.Handle("/metrics", promhttp.Handler())
	if cfg.IssueHttp > 0 {
		issueH, err := issuehandler.New(env, cfg.IssueHttp)
		if err != nil {
			return nil, err
		}

		curlcmd, err := issueH.CurlString(listenAddr, pubkeyhash)
		if err != nil {
			return nil, err
		}
		mux.Handle("/issue", issueH)
		slog.Infof("HTTP issue endpoint enabled for %d times.", cfg.IssueHttp)
		slog.Infof("  On clients, exec: %s", curlcmd)
	}
	mux.Handle("/certs/", http.StripPrefix("/certs/", certshandler.New(env)))

	httpHandler := httpzaplog.Handler{
		Upstream: mux,
		Logger:   env.Logger,
	}

	httpsrv := &http.Server{
		Addr:    listenAddr,
		Handler: grpcHttpMux(grpcServer, httpHandler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlscert},
			NextProtos:   []string{"h2"},
			ClientAuth:   tls.RequestClientCert,
		},
	}

	go func() {
		slog.Infof("Starting to accept new conn.")
		err := httpsrv.Serve(tls.NewListener(lis, httpsrv.TLSConfig))
		if err != nil && err != http.ErrServerClosed {
			slog.Warnf("httpsrv.Serve failed: %v", err)
		}
	}()
	srv := &Server{
		Shutdown: func(ctx context.Context) error {
			return httpsrv.Shutdown(ctx)
		},
	}

	if cfg.AutoShutdown > 0 {
		slog.Infof("Will start auto-shutdown after %v", cfg.AutoShutdown)
		time.AfterFunc(cfg.AutoShutdown, func() {
			slog.Infof("Starting auto-shutdown since %v passed", cfg.AutoShutdown)
			srv.Shutdown(context.Background())
		})
	}

	return srv, nil
}

func Run(ctx context.Context, env *action.Environment, cfg *Config) error {
	s, err := StartServer(ctx, env, cfg)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return s.Shutdown(ctx)
}
