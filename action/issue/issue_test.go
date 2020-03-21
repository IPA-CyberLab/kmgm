package issue_test

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/action/setup"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
	"go.uber.org/zap"
)

func init() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)
}

func testEnv(t *testing.T) (*action.Environment, func()) {
	t.Helper()

	basedir, err := ioutil.TempDir("", "kmgm_conn_test")
	if err != nil {
		t.Fatalf("ioutil.TempDir: %v", err)
	}

	stor, err := storage.New(basedir)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	env, err := action.NewEnvironment(stor)
	env.Frontend = &frontend.NonInteractive{Logger: zap.L()}

	cfg, err := setup.DefaultConfig()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := setup.Run(env, cfg); err != nil {
		t.Fatalf("setup.Run: %v", err)
	}

	return env, func() {
		os.RemoveAll(basedir)
	}
}

func TestIssue(t *testing.T) {
	env, teardown := testEnv(t)
	t.Cleanup(teardown)

	profile, err := env.Profile()
	if err != nil {
		t.Fatalf("%v", err)
	}
	cacert, err := profile.ReadCACertificate()
	if err != nil {
		t.Fatalf("%v", err)
	}

	priv, err := wcrypto.GenerateKey(env.Randr, wcrypto.KeySECP256R1, "", env.Logger)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		t.Fatalf("%v", err)
	}
	cfg, err := issue.DefaultConfig(nil)
	if err != nil {
		t.Fatalf("%v", err)
	}

	certDer, err := issue.Run(env, pub, cfg)
	if err != nil {
		t.Fatalf("issue.Run: %v", err)
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}

	certpool := x509.NewCertPool()
	certpool.AddCert(cacert)

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       certpool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("%v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       certpool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now().Add(800 * 24 * time.Hour),
	}); err != nil {
		t.Errorf("%v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       certpool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now().Add(900 * 24 * time.Hour),
	}); err == nil {
		t.Errorf("should have expired")
	}

	defer teardown()
}
