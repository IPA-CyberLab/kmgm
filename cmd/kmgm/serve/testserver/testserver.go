package testserver

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/testkmgm"
	"github.com/IPA-CyberLab/kmgm/testutils"
	"github.com/prometheus/client_golang/prometheus"
)

const BootstrapToken = "testtoken"

func RunKmgmServe(t *testing.T) (addrPort, cacertPath string) {
	t.Helper()

	r := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = r
	prometheus.DefaultGatherer = r

	basedir, teardown := testutils.PrepareBasedir(t)
	t.Cleanup(teardown)

	testPort := 34000
	addrPort = fmt.Sprintf("127.0.0.1:%d", testPort)
	cacertPath = filepath.Join(basedir, ".kmgm_server/cacert.pem")

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

	t.Cleanup(func() {
		cancel()
		<-joinC
	})
	return
}
