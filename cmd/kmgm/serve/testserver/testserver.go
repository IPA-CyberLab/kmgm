package testserver

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/testkmgm"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/testutils"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
	"github.com/prometheus/client_golang/prometheus"
)

const BootstrapToken = "testtoken"

type TestServer struct {
	AddrPort   string
	CACertPath string
	CACert     *x509.Certificate
	PubKeyHash string
}

type option struct {
	RunSetup bool
}

type Option func(*option)

func RunSetup(o *option) { o.RunSetup = true }

func Run(t *testing.T, tsos ...Option) *TestServer {
	t.Helper()

	o := &option{}
	for _, tso := range tsos {
		tso(o)
	}

	r := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = r
	prometheus.DefaultGatherer = r

	basedir := testutils.PrepareBasedir(t)

	if o.RunSetup {
		logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"setup"}, testkmgm.NowDefault)
		if err != nil {
			t.Fatalf("Failed to run setup: %v", err)
		}
		testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")
	}

	testPort := 34000
	addrPort := fmt.Sprintf("127.0.0.1:%d", testPort)
	cacertPath := filepath.Join(basedir, ".kmgm_server/cacert.pem")

	ctx, cancel := context.WithCancel(context.Background())

	joinC := make(chan struct{})
	go func() {
		logs, err := testkmgm.Run(t, ctx, basedir, nil, []string{"serve", "--reuse-port", "--listen-addr", addrPort, "--bootstrap-token", BootstrapToken}, testkmgm.NowDefault)
		_ = err // expectErr(t, err, context.Canceled) // not always reliable
		testutils.ExpectLogMessage(t, logs, "Started listening")
		close(joinC)
	}()

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", addrPort)
		if err != nil {
			t.Logf("net.Dial(%s) error: %v", addrPort, err)

			time.Sleep(100 * time.Millisecond)
			continue
		}
		conn.Close()
		t.Logf("net.Dial(%s) success", addrPort)
		break
	}

	cacert, err := storage.ReadCertificateFile(cacertPath)
	if err != nil {
		t.Fatalf("Failed to read cacert: %v", err)
	}
	pubkeyhash, err := wcrypto.PubKeyPinString(cacert.PublicKey)
	if err != nil {
		t.Fatalf("Failed to compute pubkeyhash: %v", err)
	}

	t.Cleanup(func() {
		cancel()
		<-joinC
	})
	return &TestServer{
		AddrPort:   addrPort,
		CACertPath: cacertPath,
		CACert:     cacert,
		PubKeyHash: pubkeyhash,
	}
}
