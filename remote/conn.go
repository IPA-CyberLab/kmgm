package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"

	"github.com/IPA-CyberLab/kmgm/storage"
)

type ConnectionInfo struct {
	HostPort string `yaml:"hostPort" flags:"server,host:port of kmgm server to connect to"`

	CACertificateFile string `yaml:"caCertificateFile" flags:"cacert,Path to a CA certificate to verify the kmgm server,,path"`
	PinnedPubKey      string `yaml:"pinnedPubKey" flags:"pinnedpubkey,SHA256 hash of the kmgm server publickey"`
	AllowInsecure     bool   `yaml:"allowInsecure,omitempty" flags:"insecure,skip kmgm server certificate verification (hidden),,hidden`

	ClientCertificateFile string `yaml:"clientCertificateFile" flags:"client-cert,Path to a client certificate to present to the kmgm server,,path"`
	ClientPrivateKeyFile  string `yaml:"clientPrivateKeyFile" flags:"client-priv,Path to the private key corresponding to the client certificate,,path"`

	AccessToken string `yaml:"accessToken,omitempty" flags:"token,Token string to use for server authentication when bootstrapping"`
}

func (cinfo ConnectionInfo) TransportCredentials(l *zap.Logger) (credentials.TransportCredentials, error) {
	slog := l.Sugar()

	var tc *tls.Config
	if cinfo.CACertificateFile != "" {
		cacert, err := storage.ReadCertificateFile(cinfo.CACertificateFile)
		if err != nil {
			return nil, err
		}

		cp := x509.NewCertPool()
		cp.AddCert(cacert)

		tc = &tls.Config{RootCAs: cp}
	} else {
		if cinfo.PinnedPubKey == "" && !cinfo.AllowInsecure {
			return nil, errors.New("Neither CA cert or public key pin hash was supplied to authenticate server.")
		}

		tc = &tls.Config{InsecureSkipVerify: true}
	}
	if cinfo.AccessToken != "" {
		if cinfo.ClientCertificateFile != "" {
			slog.Debugf("Ignoring ClientCertificateFile since AccessToken was provided.")
		}
	} else if cinfo.ClientCertificateFile != "" {
		if cinfo.ClientPrivateKeyFile == "" {
			return nil, errors.New("Client auth privateKey was supplied without a client certificate.")
		}

		priv, err := storage.ReadPrivateKeyFile(cinfo.ClientPrivateKeyFile)
		if err != nil {
			return nil, err
		}

		cert, err := storage.ReadCertificateFile(cinfo.ClientCertificateFile)
		if err != nil {
			return nil, err
		}

		tc.Certificates = []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  priv,
		}}
	} else {
		if cinfo.ClientPrivateKeyFile != "" {
			return nil, errors.New("Client auth certificate was supplied without a privateKey.")
		}
	}

	tcred := NewTransportCredentials(tc, cinfo.PinnedPubKey)

	return tcred, nil
}

func (cinfo ConnectionInfo) Dial(ctx context.Context, l *zap.Logger) (*grpc.ClientConn, error) {
	tcred, err := cinfo.TransportCredentials(l)
	if err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(tcred),
	}
	if cinfo.AccessToken != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: cinfo.AccessToken})
		opts = append(opts,
			grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: ts}))
	}
	conn, err := grpc.DialContext(ctx, cinfo.HostPort, opts...)
	if err != nil {
		return nil, fmt.Errorf("Failed to grpc.Dial(%q). err: %v", cinfo.HostPort, err)
	}
	return conn, nil
}
