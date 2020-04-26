package main_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

const BootstrapToken = "testtoken"

func runKmgmServe(t *testing.T) (addrPort, cacertPath string) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	testPort := 34000
	addrPort = fmt.Sprintf("127.0.0.1:%d", testPort)
	cacertPath = filepath.Join(basedir, ".kmgm_server/cacert.pem")

	ctx, cancel := context.WithCancel(context.Background())

	joinC := make(chan struct{})
	go func() {
		logs, err := runKmgm(t, ctx, basedir, nil, []string{"serve", "--reuse-port", "--listen-addr", addrPort, "--bootstrap-token", BootstrapToken}, nowDefault)
		_ = err // expectErr(t, err, context.Canceled) // not always reliable
		expectLogMessage(t, logs, "Started listening")
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

func TestServe_Noop(t *testing.T) {
	_, _ = runKmgmServe(t)
}

func TestBootstrap(t *testing.T) {
	addrPort, cacertPath := runKmgmServe(t)

	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)
	logs, err := runKmgm(t, context.Background(), basedir, nil, []string{"client", "--server", addrPort, "--cacert", cacertPath, "--token", BootstrapToken, "bootstrap"}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "Wrote server connection info to file ")
}
