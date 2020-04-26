package remote_test

import (
	"context"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/action/serve"
	"github.com/IPA-CyberLab/kmgm/action/serve/authprofile"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/remote"
	"github.com/IPA-CyberLab/kmgm/remote/hello"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

const ListenAddr = "localhost:34681"
const BootstrapToken = "testtoken"

var TestLogger *zap.Logger

func init() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)
	TestLogger = logger
}

func runTestServer(t *testing.T) (*action.Environment, *storage.Profile, func()) {
	t.Helper()

	basedir, err := ioutil.TempDir("", "kmgm_conn_test")
	if err != nil {
		t.Fatalf("ioutil.TempDir: %v", err)
	}

	stor, err := storage.New(basedir)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	env := &action.Environment{
		Storage:  stor,
		Randr:    rand.Reader,
		Frontend: &frontend.NonInteractive{Logger: TestLogger},
		Logger:   TestLogger,
		NowImpl:  time.Now,

		ProfileName: authprofile.ProfileName,
	}

	authp, err := authprofile.Ensure(env)
	if err != nil {
		t.Fatalf("authprofile.Ensuure: %v", err)
	}

	cfg := &serve.Config{
		ListenAddr: ListenAddr,
		Bootstrap: &serve.FixedTokenAuthProvider{
			Token:    BootstrapToken,
			NotAfter: time.Now().Add(15 * time.Minute),
			Logger:   env.Logger,
		},
	}

	srv, err := serve.StartServer(context.Background(), env, cfg)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	return env, authp, func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("Server.Shutdown: %v", err)
		}
		os.RemoveAll(basedir)
	}
}

func expectConnSuccess(t *testing.T, cinfo remote.ConnectionInfo, at pb.AuthenticationType) {
	t.Helper()

	ctx := context.Background()
	conn, err := cinfo.Dial(ctx, zap.L())
	if err != nil {
		t.Fatalf("cinfo.Dial: %v", err)
	}

	u, err := hello.Hello(ctx, conn, TestLogger)
	if err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if u.Type != at {
		t.Errorf("Unexpected user type: %v", u.Type)
	}
}

func expectSubconnFailure(t *testing.T, cinfo remote.ConnectionInfo) {
	ctx := context.Background()
	conn, err := cinfo.Dial(ctx, zap.L())
	if err != nil {
		t.Fatalf("cinfo.Dial: %v", err)
	}

	_, err = hello.Hello(ctx, conn, TestLogger)
	if err == nil {
		t.Errorf("subconn should have failed")
	}
}

func TestInsecureAnonymous(t *testing.T) {
	_, _, shutdownServer := runTestServer(t)
	defer shutdownServer()

	cinfo := remote.ConnectionInfo{
		HostPort: ListenAddr,

		AllowInsecure: true,
	}

	expectConnSuccess(t, cinfo, pb.AuthenticationType_ANONYMOUS)
}

func TestServerCAAnonymous(t *testing.T) {
	_, authp, shutdownServer := runTestServer(t)
	defer shutdownServer()

	cinfo := remote.ConnectionInfo{
		HostPort: ListenAddr,

		CACertificateFile: authp.CACertPath(),
	}
	expectConnSuccess(t, cinfo, pb.AuthenticationType_ANONYMOUS)
}

// FIXME[P1]: func TestServerCA_Wrong(t *testing.T)

func TestPinnedPubKeyAnonymous(t *testing.T) {
	_, authp, shutdownServer := runTestServer(t)
	defer shutdownServer()

	cert, err := storage.ReadCertificateFile(authp.CACertPath())
	if err != nil {
		t.Fatalf("ReadCertificateFile: %v", err)
	}
	pinnedpubkey, err := wcrypto.PubKeyPinString(cert.PublicKey)
	if err != nil {
		t.Fatalf("PubKeyPinString: %v", err)
	}

	cinfo := remote.ConnectionInfo{
		HostPort:     ListenAddr,
		PinnedPubKey: pinnedpubkey,
	}
	expectConnSuccess(t, cinfo, pb.AuthenticationType_ANONYMOUS)
}

func TestPinnedPubKey_Wrong(t *testing.T) {
	_, _, shutdownServer := runTestServer(t)
	defer shutdownServer()

	cinfo := remote.ConnectionInfo{
		HostPort:     ListenAddr,
		PinnedPubKey: "abcdef",
	}
	expectSubconnFailure(t, cinfo)
}

func TestServerBootstrapToken(t *testing.T) {
	_, authp, shutdownServer := runTestServer(t)
	defer shutdownServer()

	cinfo := remote.ConnectionInfo{
		HostPort: ListenAddr,

		CACertificateFile: authp.CACertPath(),

		AccessToken: BootstrapToken,
	}
	expectConnSuccess(t, cinfo, pb.AuthenticationType_BOOTSTRAP_TOKEN)
}

func TestServerClientCertAuth(t *testing.T) {
	srvEnv, authp, shutdownServer := runTestServer(t)
	defer shutdownServer()

	cliPrivPath := srvEnv.Storage.ClientPrivateKeyPath()
	cliCertPath := srvEnv.Storage.ClientCertPath()

	cliPriv, err := wcrypto.GenerateKey(rand.Reader, wcrypto.ServerKeyType, "clicert", TestLogger)
	if err != nil {
		t.Fatalf("wcrypto.GenerateKey: %v", err)
	}
	if err := storage.WritePrivateKeyFile(cliPrivPath, cliPriv); err != nil {
		t.Fatalf("WritePrivateKeyFile: %v", err)
	}

	cliPub, err := wcrypto.ExtractPublicKey(cliPriv)
	if err != nil {
		t.Fatalf("wcrypto.ExtractPublicKey: %v", err)
	}

	issueCfg, err := issue.DefaultConfig(nil)
	if err != nil {
		t.Fatalf("issue.DefaultConfig: %v", err)
	}
	issueCfg.Subject = &dname.Config{
		CommonName: "testClient",
	}
	issueCfg.Names = san.ForThisHost("localhost:12345")
	issueCfg.KeyUsage = keyusage.KeyUsageTLSClient.Clone()
	issueCfg.KeyType = wcrypto.ServerKeyType

	cliCertDer, err := issue.Run(srvEnv, cliPub, issueCfg)
	if err != nil {
		t.Fatalf("issue.Run: %v", err)
	}

	if err := storage.WriteCertificateDerFile(cliCertPath, cliCertDer); err != nil {
		t.Fatalf("WriteCertificateDerFile: %v", err)
	}

	cinfo := remote.ConnectionInfo{
		HostPort: ListenAddr,

		CACertificateFile: authp.CACertPath(),

		ClientCertificateFile: cliCertPath,
		ClientPrivateKeyFile:  cliPrivPath,
	}
	expectConnSuccess(t, cinfo, pb.AuthenticationType_CLIENT_CERT)
}
