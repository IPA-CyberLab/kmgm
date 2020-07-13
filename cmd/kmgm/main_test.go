package main_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/IPA-CyberLab/kmgm/action"
	issuea "github.com/IPA-CyberLab/kmgm/action/issue"
	setupa "github.com/IPA-CyberLab/kmgm/action/setup"
	main "github.com/IPA-CyberLab/kmgm/cmd/kmgm"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/ipapi"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

func init() {
	ipapi.MockResult = &ipapi.Result{
		RegionName:  "California",
		CountryCode: "US",
	}
}

func prepareBasedir(t *testing.T) (string, func()) {
	t.Helper()

	basedir, err := ioutil.TempDir("", "kmgm-testdir-*")
	if err != nil {
		t.Fatal(err)
	}

	return basedir, func() { os.RemoveAll(basedir) }
}

func readCACert(t *testing.T, basedir string) *x509.Certificate {
	t.Helper()

	stor, err := storage.New(basedir)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	prof, err := stor.Profile(storage.DefaultProfileName)
	if err != nil {
		t.Fatal(err)
	}

	cacert, err := prof.ReadCACertificate()
	if err != nil {
		t.Fatal(err)
	}

	return cacert
}

func readCASubject(t *testing.T, basedir string) pkix.Name {
	t.Helper()

	cacert := readCACert(t, basedir)
	return cacert.Subject
}

func mockNowImpl(t time.Time) func() time.Time {
	return func() time.Time {
		return t
	}
}

var nowDefault = time.Date(2020, time.March, 1, 0, 0, 0, 0, time.UTC)

func runKmgm(t *testing.T, ctx context.Context, basedir string, configYaml []byte, args []string, mockNow time.Time) (*observer.ObservedLogs, error) {
	t.Helper()

	app := main.NewApp()

	zobs, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(zobs)
	app.Metadata = make(map[string]interface{})
	app.Metadata["Logger"] = logger
	app.Metadata["NowImpl"] = mockNowImpl(mockNow)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	app.Writer = &stdoutBuf
	app.ErrWriter = &stderrBuf

	var tmpfile *os.File
	if configYaml != nil {
		var err error
		tmpfile, err = ioutil.TempFile("", "kmgm-testconfig-*.yml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.Write(configYaml); err != nil {
			t.Fatal(err)
		}
		// We need Close() here since we read the tmpfile later in the test.
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}
	}

	as := []string{"kmgm", "--non-interactive", "--verbose", "--basedir", basedir}
	if configYaml != nil {
		as = append(as, "--config", tmpfile.Name())
	}
	as = append(as, args...)
	err := app.RunContext(ctx, as)

	t.Logf("stdout: %s", stdoutBuf.String())
	t.Logf("stderr: %s", stderrBuf.String())
	for _, l := range logs.All() {
		t.Logf("%+v", l)
	}
	return logs, err
}

func expectLogMessage(t *testing.T, logs *observer.ObservedLogs, expectedRE string) {
	t.Helper()

	re := regexp.MustCompile(expectedRE)
	for _, l := range logs.All() {
		if re.MatchString(l.Message) {
			return
		}
	}

	t.Errorf("Could not find a log line that matches %s", expectedRE)
}

func expectErrMessage(t *testing.T, err error, expectedRE string) {
	t.Helper()

	if err == nil {
		t.Errorf("No error occured while expecting error message that match %s", expectedRE)
		return
	}

	re := regexp.MustCompile(expectedRE)

	msg := err.Error()
	if re.MatchString(msg) {
		return
	}

	t.Errorf("Error message %q doesn't match %s", msg, expectedRE)
}

func expectErr(t *testing.T, actual, expected error) {
	t.Helper()

	if errors.Is(actual, expected) {
		return
	}
	if expected == nil {
		t.Errorf("Expected no error but got error: %v", actual)
		return
	}
	t.Errorf("Expected err %v, but got err: %v", expected, actual)
}

func TestSetup_NoArgs(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	logs, err := runKmgm(t, context.Background(), basedir, nil, []string{"setup"}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "CA setup successfully completed")
}

func TestSetup_EmptyConfig(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	spaces := []byte(" \t\n")
	logs, err := runKmgm(t, context.Background(), basedir, spaces, []string{"setup"}, nowDefault)
	expectErrMessage(t, err, `was empty$`)
	_ = logs
}

func TestSetup_Default(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	yaml := []byte(`
noDefault: false

setup:
  subject:
    commonName: test
`)

	logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"setup"}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "CA setup successfully completed")
}

func TestSetup_NoDefault(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	yaml := []byte(`
noDefault: true

setup:
  subject:
    commonName: testCA

  keyType: ecdsa
  validity: farfuture
`)

	logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"setup"}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "CA setup successfully completed")

	s := readCASubject(t, basedir)

	if len(s.Country) != 0 {
		t.Errorf("Expected no Country for noDefault: true setups, but got %+v", s.Country)
	}
}
func TestSetup_NoDefault_NoKeyType(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	yaml := []byte(`
noDefault: true

setup:
  subject:
    commonName: testCA

  validity: farfuture
`)

	logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"setup"}, nowDefault)
	// FIXME[P1]: Better error message
	expectErrMessage(t, err, "Unknown key type: any")
	_ = logs
}

func TestSetup_Flags(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	logs, err := runKmgm(t, context.Background(), basedir, nil, []string{"setup", "--country", "JP"}, nowDefault)
	expectErr(t, err, nil)
	_ = logs

	s := readCASubject(t, basedir)
	t.Logf("subj: %v", s)

	if s.CommonName == "" {
		t.Errorf("Expected non-empty CommonName, but got empty")
	}

	if s.Province[0] != "California" {
		t.Errorf("Wrong Province %+v", s.Province)
	}

	if s.Country[0] != "JP" {
		t.Errorf("wrong country %q", s.Country[0])
	}
}

func TestSetup_NoDefault_Flags(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	logs, err := runKmgm(t, context.Background(), basedir, nil, []string{"--no-default", "setup", "--country", "JP", "--key-type", "rsa", "--validity", "7d"}, nowDefault)
	expectErr(t, err, nil)
	_ = logs

	s := readCASubject(t, basedir)

	if s.CommonName != "" {
		t.Errorf("Expected no CommonName, but got %v", s.CommonName)
	}

	if len(s.Province) != 0 {
		t.Errorf("Expected no Province, but got %+v", s.Province)
	}

	if s.Country[0] != "JP" {
		t.Errorf("wrong country %q", s.Country[0])
	}
}

func TestIssue_NoCA(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	logs, err := runKmgm(t, context.Background(), basedir, nil, []string{"issue"}, nowDefault)
	expectErr(t, err, setup.CantRunInteractiveCASetupErr)
	_ = logs //expectLogMessage(t, logs, "")
}

func testEnv(t *testing.T, basedir string, mockNow time.Time) *action.Environment {
	stor, err := storage.New(basedir)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	fe := &frontend.NonInteractive{
		Logger: zap.L(),
	}

	env, err := action.NewEnvironment(fe, stor)
	env.Frontend = &frontend.NonInteractive{Logger: zap.L()}
	env.NowImpl = mockNowImpl(mockNow)

	return env
}

func setupCA(t *testing.T, basedir string) {
	t.Helper()

	mockNow := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	env := testEnv(t, basedir, mockNow)

	cfg := &setupa.Config{
		Subject: &dname.Config{
			CommonName:         "test_CA_CN",
			Organization:       "test_CA_Org",
			OrganizationalUnit: "test_CA_OU",
			Country:            "JP",
			Locality:           "test_CA_L",
			Province:           "test_CA_P",
			StreetAddress:      "test_CA_SA",
			PostalCode:         "test_CA_PC",
		},
		KeyType: wcrypto.KeyRSA4096,
	}
	cfg.Validity.UnmarshalFlag("1y")
	if err := cfg.Verify(time.Now()); err != nil {
		t.Fatalf("cfg.Verify: %v", err)
	}
	if err := setupa.Run(env, cfg); err != nil {
		t.Fatalf("setup.Run: %v", err)
	}
}

func TestSetup_AlreadyExists(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	setupCA(t, basedir)

	t.Run("Default", func(t *testing.T) {
		logs, err := runKmgm(t, context.Background(), basedir, nil, []string{"setup"}, nowDefault)
		expectErr(t, err, nil)
		expectLogMessage(t, logs, "already has a CA setup.")
	})

	t.Run("NoDefault_MatchingConfig", func(t *testing.T) {
		yaml := []byte(`
      setup:
        subject:
          commonName: test_CA_CN
          organization: test_CA_Org
          organizationalUnit: test_CA_OU
          country: JP
          locality: test_CA_L
          province: test_CA_P
          streetAddress: test_CA_SA
          postalCode: test_CA_PC
        keyType: rsa
        validity: 1y

      noDefault: true
      `)
		logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"setup"}, nowDefault)
		expectErr(t, err, nil)
		expectLogMessage(t, logs, "already has a CA setup.")
	})

	t.Run("NoDefault_IncompatibleSubject", func(t *testing.T) {
		yaml := []byte(`
      setup:
        subject:
          commonName: test_CA_CN
          organization: wrong_Org
          organizationalUnit: test_CA_OU
          country: JP
          locality: test_CA_L
          province: test_CA_P
          streetAddress: test_CA_SA
          postalCode: test_CA_PC
        keyType: rsa
        validity: 1y

      noDefault: true
      `)
		_, err := runKmgm(t, context.Background(), basedir, yaml, []string{"setup"}, nowDefault)
		expectErr(t, err, setup.IncompatibleCertErr{})
	})

	t.Run("NoDefault_IncompatibleKeyType", func(t *testing.T) {
		yaml := []byte(`
      setup:
        subject:
          commonName: test_CA_CN
          organization: test_CA_Org
          organizationalUnit: test_CA_OU
          country: JP
          locality: test_CA_L
          province: test_CA_P
          streetAddress: test_CA_SA
          postalCode: test_CA_PC
        keyType: ecdsa
        validity: 1y

      noDefault: true
      `)
		_, err := runKmgm(t, context.Background(), basedir, yaml, []string{"setup"}, nowDefault)
		expectErr(t, err, setup.IncompatibleCertErr{})
	})
}

func TestIssue_Default(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	setupCA(t, basedir)

	certPath := filepath.Join(basedir, "issue.cert.pem")
	logs, err := runKmgm(t, context.Background(), basedir, nil, []string{"issue",
		"--priv", filepath.Join(basedir, "issue.priv.pem"),
		"--cert", certPath,
		"--cn", "leaf_CN",
	}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "Generating certificate... Done.")

	cert, err := storage.ReadCertificateFile(certPath)
	if err != nil {
		t.Fatalf("cert read: %v", err)
	}

	ss := cert.Subject.String()
	if ss != "CN=leaf_CN,OU=test_CA_OU,O=test_CA_Org,POSTALCODE=test_CA_PC,STREET=test_CA_SA,L=test_CA_L,ST=test_CA_P,C=JP" {
		t.Errorf("subj: %s", cert.Subject.String())
	}
}

func TestIssue_Yaml(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	setupCA(t, basedir)

	yaml := []byte(`
issue:
  subject:
    commonName: leaf_CN
  keyType: rsa
  keyUsage:
    preset: tlsClientServer
  validity: 30d

noDefault: true
`)

	certPath := filepath.Join(basedir, "issue.cert.pem")
	logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue",
		"--priv", filepath.Join(basedir, "issue.priv.pem"),
		"--cert", certPath,
	}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "Generating certificate... Done.")

	cert, err := storage.ReadCertificateFile(certPath)
	if err != nil {
		t.Fatalf("cert read: %v", err)
	}

	ss := cert.Subject.String()
	if ss != "CN=leaf_CN" {
		t.Errorf("subj: %s", cert.Subject.String())
	}
}

func TestIssue_WrongKeyType(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	setupCA(t, basedir)

	privPath := filepath.Join(basedir, "issue.priv.pem")
	priv, err := wcrypto.GenerateKey(rand.Reader, wcrypto.KeySECP256R1, "", zap.L())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := storage.WritePrivateKeyFile(privPath, priv); err != nil {
		t.Fatalf("%v", err)
	}

	certPath := filepath.Join(basedir, "issue.cert.pem")
	yaml := []byte(fmt.Sprintf(`
issue:
  subject:
    commonName: leaf_CN
  keyType: rsa
  keyUsage:
    preset: tlsClientServer
  validity: 30d

certPath: %s
privateKeyPath: %s

noDefault: true
`, certPath, privPath))

	logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, nowDefault)
	expectErr(t, err, wcrypto.UnexpectedKeyTypeErr{})
	_ = logs
}

func TestIssue_UseExistingKey(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	setupCA(t, basedir)

	privPath := filepath.Join(basedir, "issue.priv.pem")
	priv, err := wcrypto.GenerateKey(rand.Reader, wcrypto.KeyRSA4096, "", zap.L())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := storage.WritePrivateKeyFile(privPath, priv); err != nil {
		t.Fatalf("%v", err)
	}

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		t.Fatalf("%v", err)
	}

	certPath := filepath.Join(basedir, "issue.cert.pem")
	yaml := []byte(fmt.Sprintf(`
issue:
  subject:
    commonName: leaf_CN
  keyType: rsa
  keyUsage:
    preset: tlsClientServer
  validity: 30d

certPath: %s
privateKeyPath: %s

noDefault: true
`, certPath, privPath))

	logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "Generating certificate... Done.")

	cert, err := storage.ReadCertificateFile(certPath)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if err := wcrypto.VerifyPublicKeyMatch(cert.PublicKey, pub); err != nil {
		t.Errorf("VerifyPublicKey: %v", err)
	}
}

// FIXME[P2]: use exiting key scenario
// - existing ecdsa key, use default -> shouldn't warn
// - existing ecdsa key, specified rsa -> fail
// - existing ecdsa key, specified ecdsa -> pass

// FIXME[P2]: test expired ca
// FIXME[P2]: dump-template renewal yaml

func setupCertAtPath(t *testing.T, basedir string, pub crypto.PublicKey, certPath string) {
	t.Helper()

	mockNow := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)
	env := testEnv(t, basedir, mockNow)

	cfg := &issuea.Config{
		Subject: &dname.Config{
			CommonName:         "test_leaf_CN",
			Organization:       "test_leaf_Org",
			OrganizationalUnit: "test_leaf_OU",
			Country:            "DE",
			Locality:           "test_leaf_L",
			Province:           "test_leaf_P",
			StreetAddress:      "test_leaf_SA",
			PostalCode:         "test_leaf_PC",
		},
		Names:    san.MustParse("san.example,192.168.0.10"),
		KeyUsage: keyusage.KeyUsageTLSClientServer.Clone(),
		Validity: period.ValidityPeriod{Days: 12},
		KeyType:  wcrypto.KeyRSA4096,
	}

	certDer, err := issuea.Run(env, pub, cfg)
	if err != nil {
		t.Fatalf("issue.Run: %v", err)
	}

	if err := storage.WriteCertificateDerFile(certPath, certDer); err != nil {
		t.Fatalf("WriteCertificateDerFile: %v", err)
	}
}

func setupCert(t *testing.T, basedir string, pub crypto.PublicKey) string {
	t.Helper()

	certPath := filepath.Join(basedir, "issue.cert.pem")
	setupCertAtPath(t, basedir, pub, certPath)
	return certPath
}

func TestIssue_RenewCert_NoDefault(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	setupCA(t, basedir)

	privPath := filepath.Join(basedir, "issue.priv.pem")
	priv, err := wcrypto.GenerateKey(rand.Reader, wcrypto.KeyRSA4096, "", zap.L())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := storage.WritePrivateKeyFile(privPath, priv); err != nil {
		t.Fatalf("%v", err)
	}

	pub, err := wcrypto.ExtractPublicKey(priv)
	if err != nil {
		t.Fatalf("%v", err)
	}
	certPath := setupCert(t, basedir, pub)

	t.Run("SubjectMismatch", func(t *testing.T) {
		yaml := []byte(fmt.Sprintf(`
      issue:
        subject:
          commonName: different_commonName
        subjectAltNames: ["san.example", "192.168.0.10"]
        keyType: rsa
        keyUsage:
          preset: tlsClientServer
        validity: 30d

      certPath: %s
      privateKeyPath: %s

      noDefault: true
      `, certPath, privPath))

		logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, nowDefault)
		expectErr(t, err, issue.IncompatibleCertErr{})
		_ = logs
	})

	t.Run("SanMismatch", func(t *testing.T) {
		yaml := []byte(fmt.Sprintf(`
      issue:
        subject:
          commonName: test_leaf_CN
        subjectAltNames: ["foo.example", "192.168.0.10"]
        keyType: rsa
        keyUsage:
          preset: tlsClientServer
        validity: 30d

      certPath: %s
      privateKeyPath: %s

      noDefault: true
      `, certPath, privPath))

		logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, nowDefault)
		expectErr(t, err, issue.IncompatibleCertErr{})
		_ = logs
	})

	t.Run("KeyUsageMismatch", func(t *testing.T) {
		yaml := []byte(fmt.Sprintf(`
      issue:
        subject:
          commonName: test_leaf_CN
          organization: test_leaf_Org
          organizationalUnit: test_leaf_OU
          country: DE
          locality: test_leaf_L
          province: test_leaf_P
          streetAddress: test_leaf_SA
          postalCode: test_leaf_PC
        keyType: rsa
        keyUsage:
          preset: tlsClient
        validity: 30d

      certPath: %s
      privateKeyPath: %s

      noDefault: true
      `, certPath, privPath))

		logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, nowDefault)
		expectErr(t, err, issue.IncompatibleCertErr{})
		_ = logs
	})

	// FIXME[P2]: Wrong key (priv.pub doesn't match cert pub)

	t.Run("RenewBefore_NotSpecified", func(t *testing.T) {
		yaml := []byte(fmt.Sprintf(`
      issue:
        subject:
          commonName: test_leaf_CN
          organization: test_leaf_Org
          organizationalUnit: test_leaf_OU
          country: DE
          locality: test_leaf_L
          province: test_leaf_P
          streetAddress: test_leaf_SA
          postalCode: test_leaf_PC
        subjectAltNames: ["san.example", "192.168.0.10"]
        keyType: rsa
        keyUsage:
          preset: tlsClientServer
        validity: 30d

      certPath: %s
      privateKeyPath: %s

      noDefault: true
      `, certPath, privPath))

		logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, nowDefault)
		expectErr(t, err, nil)
		expectLogMessage(t, logs, "Generating certificate... Done.")

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			t.Fatalf("%v", err)
		}

		if err := wcrypto.VerifyPublicKeyMatch(cert.PublicKey, pub); err != nil {
			t.Errorf("VerifyPublicKey: %v", err)
		}
		if nowDefault.Sub(cert.NotBefore) > time.Hour {
			t.Errorf("cert.NotBefore not updated. Renew failed.")
		}
	})

	t.Run("RenewBefore_NotYet", func(t *testing.T) {
		certPath := filepath.Join(basedir, "renewBefore.cert.pem")
		setupCertAtPath(t, basedir, pub, certPath)

		yaml := []byte(fmt.Sprintf(`
      issue:
        subject:
          commonName: test_leaf_CN
          organization: test_leaf_Org
          organizationalUnit: test_leaf_OU
          country: DE
          locality: test_leaf_L
          province: test_leaf_P
          streetAddress: test_leaf_SA
          postalCode: test_leaf_PC
        subjectAltNames: ["san.example", "192.168.0.10"]
        keyType: rsa
        keyUsage:
          preset: tlsClientServer
        validity: 30d

      certPath: %s
      privateKeyPath: %s
      renewBefore: 10d

      noDefault: true
      `, certPath, privPath))

		now := time.Date(2020, time.February, 2, 0, 0, 0, 0, time.UTC)
		logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, now)
		expectErr(t, err, issue.CertStillValidErr{})
		if ec := main.ExitCodeOfError(err); ec != 10 {
			t.Errorf("unexpected ec: %d", ec)
		}
		_ = logs

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if now.Sub(cert.NotBefore) < time.Hour {
			t.Errorf("Shouldn't have renewed, but renewed: cert.NotBefore %v", cert.NotBefore)
		}
	})

	t.Run("RenewBefore_ExpireSoon", func(t *testing.T) {
		certPath := filepath.Join(basedir, "renewBefore.cert.pem")
		setupCertAtPath(t, basedir, pub, certPath)

		yaml := []byte(fmt.Sprintf(`
      issue:
        subject:
          commonName: test_leaf_CN
          organization: test_leaf_Org
          organizationalUnit: test_leaf_OU
          country: DE
          locality: test_leaf_L
          province: test_leaf_P
          streetAddress: test_leaf_SA
          postalCode: test_leaf_PC
        subjectAltNames: ["san.example", "192.168.0.10"]
        keyType: rsa
        keyUsage:
          preset: tlsClientServer
        validity: 30d

      certPath: %s
      privateKeyPath: %s
      renewBefore: 10d

      noDefault: true
      `, certPath, privPath))

		now := time.Date(2020, time.February, 10, 0, 0, 0, 0, time.UTC)
		logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"issue"}, now)
		expectErr(t, err, nil)
		_ = logs

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if now.Sub(cert.NotBefore) > time.Hour {
			t.Errorf("Shouldn't have renewed, but renewed: cert.NotBefore %v", cert.NotBefore)
		}
	})
}

func Test_NameConstraints(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	yaml := []byte(`
noDefault: true

setup:
  subject:
    commonName: testCA

  keyType: ecdsa
  validity: farfuture

  nameConstraints:
  - my.example
  - 192.168.10.0/24
  - -bad.my.example
`)

	logs, err := runKmgm(t, context.Background(), basedir, yaml, []string{"setup"}, nowDefault)
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "CA setup successfully completed")

	cacert := readCACert(t, basedir)
	certpool := x509.NewCertPool()
	certpool.AddCert(cacert)

	t.Run("Success", func(t *testing.T) {
		privPath := filepath.Join(basedir, "issue.priv.pem")
		certPath := filepath.Join(basedir, "issue.cert.pem")
		issueYaml := []byte(fmt.Sprintf(`
issue:
  subject:
    commonName: leaf_CN
  subjectAltNames:
    - my.example
    - sub.my.example
    - 192.168.10.123
  keyType: rsa
  keyUsage:
    preset: tlsClientServer
  validity: 30d

certPath: %s
privateKeyPath: %s

noDefault: true
`, certPath, privPath))
		logs, err = runKmgm(t, context.Background(), basedir, issueYaml, []string{"issue"}, nowDefault)
		expectErr(t, err, nil)
		_ = logs

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			t.Fatalf("cert read: %v", err)
		}

		if _, err := cert.Verify(x509.VerifyOptions{
			DNSName:     "my.example",
			Roots:       certpool,
			CurrentTime: nowDefault,
		}); err != nil {
			t.Errorf("cert verify: %v", err)
		}

		if _, err := cert.Verify(x509.VerifyOptions{
			DNSName:     "192.168.10.123",
			Roots:       certpool,
			CurrentTime: nowDefault,
		}); err != nil {
			t.Errorf("cert verify: %v", err)
		}
	})

	// FIXME[P2]: check if specified san conforms to name constraints of the CA.
}
