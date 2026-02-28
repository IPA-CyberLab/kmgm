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

	grpcprom "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	metautils "github.com/grpc-ecosystem/go-grpc-middleware/v2/metadata"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
	"github.com/IPA-CyberLab/kmgm/exporter"
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

func generateAuthFunc(authp *storage.Profile, tauth TokenAuthProvider) (auth.AuthFunc, error) {
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

		ctx = user.NewContext(ctx, u)
		return ctx, nil
	}
	return authfunc, nil
}

func zapLogger(logger *zap.Logger) logging.Logger {
	return logging.LoggerFunc(func(_ context.Context, level logging.Level, msg string, fields ...any) {
		var zapLevel zapcore.Level
		switch {
		case level <= logging.LevelDebug:
			zapLevel = zapcore.DebugLevel
		case level <= logging.LevelInfo:
			zapLevel = zapcore.InfoLevel
		case level <= logging.LevelWarn:
			zapLevel = zapcore.WarnLevel
		default:
			zapLevel = zapcore.ErrorLevel
		}

		zapFields := make([]zap.Field, 0, len(fields)/2)
		for i := 0; i+1 < len(fields); i += 2 {
			key, ok := fields[i].(string)
			if !ok {
				continue
			}
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}

		if ce := logger.Check(zapLevel, msg); ce != nil {
			ce.Write(zapFields...)
		}
	})
}

type Server struct {
	Shutdown func(ctx context.Context) error
}

func StartServer(ctx context.Context, env *action.Environment, cfg *Config) (*Server, error) {
	slog := env.Logger.Sugar().Named("StartServer")

	if cfg.Names.Empty() {
		ns, err := san.ForListenAddr(cfg.ListenAddr)
		if err != nil {
			slog.Warnf("Failed to construct subjectAltNames for listenAddr %q: %v", cfg.ListenAddr, err)
		}

		ns.Concat(san.ForThisHost())

		cfg.Names = ns
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
			if !cfg.ReusePort {
				return nil
			}

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

	serverMetrics := grpcprom.NewServerMetrics()

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(tlscert)),
		grpc.ChainUnaryInterceptor(
			auth.UnaryServerInterceptor(authfunc),
			logging.UnaryServerInterceptor(zapLogger(env.Logger)),
			serverMetrics.UnaryServerInterceptor(),
		),
	)
	pb.RegisterHelloServiceServer(grpcServer, &helloService{})
	pb.RegisterVersionServiceServer(grpcServer, &versionService{})
	certsvc, err := certificateservice.New(env)
	if err != nil {
		return nil, err
	}
	pb.RegisterCertificateServiceServer(grpcServer, certsvc)
	reflection.Register(grpcServer)

	serverMetrics.InitializeMetrics(grpcServer)
	collector := exporter.NewCollector(env.Storage, env.Logger)
	if err := env.Registerer.Register(collector); err != nil {
		return nil, fmt.Errorf("Failed to register Prometheus collector: %w", err)
	}
	if err := env.Registerer.Register(serverMetrics); err != nil {
		return nil, fmt.Errorf("Failed to register Prometheus server metrics: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})
	if cfg.ExposeMetrics {
		mux.Handle("/metrics", promhttp.Handler())
	}
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
