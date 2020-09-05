package main_test

import (
	"context"
	"testing"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/serve/testserver"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/testkmgm"
	"github.com/IPA-CyberLab/kmgm/testutils"
)

func TestServe_Noop(t *testing.T) {
	_, _ = testserver.RunKmgmServe(t)
}

func TestBootstrap(t *testing.T) {
	addrPort, cacertPath := testserver.RunKmgmServe(t)

	basedir, teardown := testutils.PrepareBasedir(t)
	t.Cleanup(teardown)
	logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"client", "--server", addrPort, "--cacert", cacertPath, "--token", testserver.BootstrapToken, "bootstrap"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "Wrote server connection info to file ")
}
