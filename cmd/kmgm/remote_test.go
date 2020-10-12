package main_test

import (
	"context"
	"testing"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/serve/testserver"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/testkmgm"
	"github.com/IPA-CyberLab/kmgm/testutils"
)

func TestServe_Noop(t *testing.T) {
	_ = testserver.Run(t)
}

func TestBootstrap(t *testing.T) {
	ts := testserver.Run(t)

	basedir := testutils.PrepareBasedir(t)
	logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"client", "--server", ts.AddrPort, "--cacert", ts.CACertPath, "--token", testserver.BootstrapToken, "bootstrap"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "Wrote server connection info to file ")
}
