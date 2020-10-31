package main_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/serve/testserver"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/testkmgm"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/testutils"
)

func TestServe_Noop(t *testing.T) {
	_ = testserver.Run(t)
}

func Test(t *testing.T) {
	ts := testserver.Run(t)
	basedir := testutils.PrepareBasedir(t)

	t.Run("bootstrap", func(t *testing.T) {
		logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"client", "--server", ts.AddrPort, "--cacert", ts.CACertPath, "--token", testserver.BootstrapToken, "bootstrap"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, nil)
		testutils.ExpectLogMessage(t, logs, "Wrote server connection info to file ")
	})

	t.Run("nonexistent profile", func(t *testing.T) {
		_, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"--profile", "noexist", "client", "issue"}, testkmgm.NowDefault)
		testutils.ExpectErrMessage(t, err, `Can't issue certificate from CA profile "noexist"`)
	})

	t.Run("specify profile", func(t *testing.T) {
		yaml := []byte(`
noDefault: false

setup:
  subject:
    commonName: myCA
`)
		logs, err := testkmgm.Run(t, context.Background(), ts.Basedir, yaml, []string{"--profile", "myprofile", "setup"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, nil)
		testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")

		certPath := filepath.Join(basedir, "issue.cert.pem")
		logs, err = testkmgm.Run(t, context.Background(), basedir, nil, []string{"--profile", "myprofile", "client", "issue", "--cert", certPath}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, nil)
		testutils.ExpectLogMessage(t, logs, `Generating certificate... Done.`)

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			t.Fatalf("cert read: %v", err)
		}

		if cert.Issuer.CommonName != "myCA" {
			t.Fatalf("unexpected cert issuer: %s", cert.Issuer.CommonName)
		}
	})

}
