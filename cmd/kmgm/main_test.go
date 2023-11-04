package main_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"go.uber.org/zap"

	issuea "github.com/IPA-CyberLab/kmgm/action/issue"
	setupa "github.com/IPA-CyberLab/kmgm/action/setup"
	main "github.com/IPA-CyberLab/kmgm/cmd/kmgm"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/issue"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/testkmgm"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/testutils"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

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

func TestSetup_NoArgs(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

	logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"setup"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")
}

func TestSetup_EmptyConfig(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

	spaces := []byte(" \t\n")
	logs, err := testkmgm.Run(t, context.Background(), basedir, spaces, []string{"setup"}, testkmgm.NowDefault)
	testutils.ExpectErrMessage(t, err, `was empty$`)
	_ = logs
}

func TestSetup_Default(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

	yaml := []byte(fmt.Sprintf(`
noDefault: false

setup:
  subject:
    commonName: test

copyCACertPath: %s
`, filepath.Join(basedir, "out/cacert.pem")))

	logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"setup"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")
	testutils.ExpectFile(t, basedir, "out/cacert.pem")
}

func TestSetup_NoDefault(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

	yaml := []byte(`
noDefault: true

setup:
  subject:
    commonName: testCA

  keyType: ecdsa
  validity: farfuture
`)

	logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"setup"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")

	s := readCASubject(t, basedir)

	if len(s.Country) != 0 {
		t.Errorf("Expected no Country for noDefault: true setups, but got %+v", s.Country)
	}
}
func TestSetup_NoDefault_NoKeyType(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

	yaml := []byte(`
noDefault: true

setup:
  subject:
    commonName: testCA

  validity: farfuture
`)

	logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"setup"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, setupa.ErrKeyTypeAny)
	_ = logs
}

func TestSetup_Flags(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

	logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"setup", "--country", "JP"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
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
	basedir := testutils.PrepareBasedir(t)

	logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"--no-default", "setup", "--country", "JP", "--key-type", "rsa", "--validity", "7d"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
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
	basedir := testutils.PrepareBasedir(t)

	logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"issue"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, setup.CantRunInteractiveCASetupErr)
	_ = logs //testutils.ExpectLogMessage(t, logs, "")
}

func setupCA(t *testing.T, basedir string) {
	t.Helper()

	mockNow := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	env := testkmgm.Env(t, basedir, mockNow)

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
	basedir := testutils.PrepareBasedir(t)

	setupCA(t, basedir)

	t.Run("Default", func(t *testing.T) {
		logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"setup"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, nil)
		testutils.ExpectLogMessage(t, logs, "already has a CA setup.")
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
		logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"setup"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, nil)
		testutils.ExpectLogMessage(t, logs, "already has a CA setup.")
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
		_, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"setup"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, setup.IncompatibleCertErr{})
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
		_, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"setup"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, setup.IncompatibleCertErr{})
	})
}

func TestIssue_Default(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

	setupCA(t, basedir)

	certPath := filepath.Join(basedir, "issue.cert.pem")
	logs, err := testkmgm.Run(t, context.Background(), basedir, nil, []string{"issue",
		"--priv", filepath.Join(basedir, "issue.priv.pem"),
		"--cert", certPath,
		"--cn", "leaf_CN",
	}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "Generating leaf certificate... Done.")

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
	basedir := testutils.PrepareBasedir(t)

	setupCA(t, basedir)

	yaml := []byte(`
issue:
  subject:
    commonName: leaf_CN
  keyType: rsa
  keyUsage:
    preset: tlsClientServer
  validity: 30d

renewBefore: 10d
noDefault: true
`)

	certPath := filepath.Join(basedir, "issue.cert.pem")
	logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue",
		"--priv", filepath.Join(basedir, "issue.priv.pem"),
		"--cert", certPath,
	}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "Generating leaf certificate... Done.")

	cert, err := storage.ReadCertificateFile(certPath)
	if err != nil {
		t.Fatalf("cert read: %v", err)
	}

	ss := cert.Subject.String()
	if ss != "CN=leaf_CN" {
		t.Errorf("subj: %s", cert.Subject.String())
	}
}

func TestIssue_NoDefault_RequireRenewBeforeToBeSet(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

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
	_, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue",
		"--priv", filepath.Join(basedir, "issue.priv.pem"),
		"--cert", certPath,
	}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, issue.RenewBeforeMustNotBeAutoIfNoDefaultErr)
	testutils.ExpectFileNotExist(t, basedir, "issue.cert.pem")
}

func TestIssue_WrongKeyType(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

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

	logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, wcrypto.UnexpectedKeyTypeErr{})
	_ = logs
}

func TestIssue_UseExistingKey(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

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
renewBefore: 10d

noDefault: true
`, certPath, privPath))

	logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "Generating leaf certificate... Done.")

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
	env := testkmgm.Env(t, basedir, mockNow)

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

func serialNumberStringOfCertAtPath(path string) string {
	cert, err := storage.ReadCertificateFile(path)
	if err != nil {
		panic(err)
	}
	return cert.SerialNumber.String()
}

func setupCert(t *testing.T, basedir string, pub crypto.PublicKey) string {
	t.Helper()

	certPath := filepath.Join(basedir, "issue.cert.pem")
	setupCertAtPath(t, basedir, pub, certPath)
	return certPath
}

func TestIssue_RenewCert(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

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
      renewBefore: 10d

      noDefault: true
      `, certPath, privPath))

		logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, issue.IncompatibleCertErr{})
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
      renewBefore: 10d

      noDefault: true
      `, certPath, privPath))

		logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, issue.IncompatibleCertErr{})
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
      renewBefore: 10d

      noDefault: true
      `, certPath, privPath))

		logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, issue.IncompatibleCertErr{})
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
      `, certPath, privPath))

		logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, testkmgm.NowDefault.Add(time.Hour*24))
		testutils.ExpectErr(t, err, nil)
		testutils.ExpectLogMessage(t, logs, "Generating leaf certificate... Done.")

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			t.Fatalf("%v", err)
		}

		if err := wcrypto.VerifyPublicKeyMatch(cert.PublicKey, pub); err != nil {
			t.Errorf("VerifyPublicKey: %v", err)
		}
		if testkmgm.NowDefault.Sub(cert.NotBefore) > time.Hour {
			t.Errorf("cert.NotBefore not updated. Renew failed.")
		}
	})

	t.Run("RenewBefore_NotYet", func(t *testing.T) {
		certPath := filepath.Join(basedir, "renewBefore.cert.pem")
		setupCertAtPath(t, basedir, pub, certPath)
		snOriginal := serialNumberStringOfCertAtPath(certPath)

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
		logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, now)
		testutils.ExpectErr(t, err, issue.CertStillValidErr{})
		if ec := main.ExitCodeOfError(err); ec != 10 {
			t.Errorf("unexpected ec: %d", ec)
		}
		_ = logs

		snNew := serialNumberStringOfCertAtPath(certPath)
		if snNew != snOriginal {
			t.Errorf("Shouldn't have renewed, but renewed.")
		}
	})

	t.Run("RenewBefore_ExpireSoon", func(t *testing.T) {
		certPath := filepath.Join(basedir, "renewBefore.cert.pem")
		setupCertAtPath(t, basedir, pub, certPath)
		snOriginal := serialNumberStringOfCertAtPath(certPath)

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
		logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"issue"}, now)
		testutils.ExpectErr(t, err, nil)
		_ = logs

		snNew := serialNumberStringOfCertAtPath(certPath)
		if snNew == snOriginal {
			t.Errorf("Should have renewed, but not renewed")
		}
	})
}

func Test_NameConstraints(t *testing.T) {
	basedir := testutils.PrepareBasedir(t)

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

	logs, err := testkmgm.Run(t, context.Background(), basedir, yaml, []string{"setup"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")

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

renewBefore: immediately
certPath: %s
privateKeyPath: %s

noDefault: true
`, certPath, privPath))
		logs, err = testkmgm.Run(t, context.Background(), basedir, issueYaml, []string{"issue"}, testkmgm.NowDefault)
		testutils.ExpectErr(t, err, nil)
		_ = logs

		cert, err := storage.ReadCertificateFile(certPath)
		if err != nil {
			t.Fatalf("cert read: %v", err)
		}

		if _, err := cert.Verify(x509.VerifyOptions{
			DNSName:     "my.example",
			Roots:       certpool,
			CurrentTime: testkmgm.NowDefault,
		}); err != nil {
			t.Errorf("cert verify: %v", err)
		}

		if _, err := cert.Verify(x509.VerifyOptions{
			DNSName:     "192.168.10.123",
			Roots:       certpool,
			CurrentTime: testkmgm.NowDefault,
		}); err != nil {
			t.Errorf("cert verify: %v", err)
		}
	})

	// FIXME[P2]: check if specified san conforms to name constraints of the CA.
}

func Test_Batch_Default(t *testing.T) {
	basedirDummy := testutils.PrepareBasedir(t)
	basedirReal := testutils.PrepareBasedir(t)

	tmpl := `
baseDir: {{ .BaseDirReal }}
profile: batchTestCA

setup:
  subject:
    commonName: batchTestCA

copyCACertPath: {{ .BaseDirReal }}/out/ca.cert.pem

issues:
- certPath: {{ .BaseDirReal }}/out/leaf1.cert.pem
  privateKeyPath: {{ .BaseDirReal }}/out/leaf1.priv.pem
  issue:
    subject:
      commonName: leaf1
- certPath: {{ .BaseDirReal }}/out/leaf2.cert.pem
  privateKeyPath: {{ .BaseDirReal }}/out/leaf2.priv.pem
  issue:
    subject:
      commonName: leaf2
`
	tmplParsed := template.Must(template.New("batchTestCA").Parse(tmpl))

	var yaml bytes.Buffer
	if err := tmplParsed.Execute(&yaml, struct {
		BaseDirReal string
	}{
		BaseDirReal: basedirReal,
	}); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	nowT := testkmgm.NowDefault
	logs, err := testkmgm.Run(t, context.Background(), basedirDummy, yaml.Bytes(),
		[]string{"batch"}, nowT)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")
	testutils.ExpectEmptyDir(t, basedirDummy)
	testutils.ExpectFile(t, basedirReal, "out/ca.cert.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf1.cert.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf1.priv.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf2.cert.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf2.priv.pem")

	cert, err := storage.ReadCertificateFile(filepath.Join(basedirReal, "out/leaf1.cert.pem"))
	if err != nil {
		t.Errorf("Failed to ReadCertificateFile: %v", err)
	}
	if cert.Subject.String() != "CN=leaf1,O=host.example,ST=California,C=US" {
		t.Errorf("Unexpected subject: %v", cert.Subject.String())
	}
}

func Test_Batch_NoDefault(t *testing.T) {
	basedirDummy := testutils.PrepareBasedir(t)
	basedirReal := testutils.PrepareBasedir(t)

	tmpl := `
noDefault: true

baseDir: {{ .BaseDirReal }}
profile: batchTestCA

setup:
  subject:
    commonName: batchTestCA

  validity: farfuture
  keyType: ecdsa

copyCACertPath: {{ .BaseDirReal }}/out/ca.cert.pem

issues:
- certPath: {{ .BaseDirReal }}/out/leaf1.cert.pem
  privateKeyPath: {{ .BaseDirReal }}/out/leaf1.priv.pem
  renewBefore: 10d
  issue:
    subject:
      commonName: leaf1
    keyUsage:
      preset: tlsClientServer
    validity: 30d
- certPath: {{ .BaseDirReal }}/out/leaf2.cert.pem
  privateKeyPath: {{ .BaseDirReal }}/out/leaf2.priv.pem
  renewBefore: 10d
  issue:
    subject:
      commonName: leaf2
    keyUsage:
      preset: tlsClientServer
    validity: 30d
`
	tmplParsed := template.Must(template.New("batchTestCA").Parse(tmpl))

	var yaml bytes.Buffer
	if err := tmplParsed.Execute(&yaml, struct {
		BaseDirReal string
	}{
		BaseDirReal: basedirReal,
	}); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	nowT := testkmgm.NowDefault
	logs, err := testkmgm.Run(t, context.Background(), basedirDummy, yaml.Bytes(),
		[]string{"batch"}, nowT)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")
	testutils.ExpectEmptyDir(t, basedirDummy)
	testutils.ExpectFile(t, basedirReal, "out/ca.cert.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf1.cert.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf1.priv.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf2.cert.pem")
	testutils.ExpectFile(t, basedirReal, "out/leaf2.priv.pem")
	snLeaf1 := serialNumberStringOfCertAtPath(filepath.Join(basedirReal, "out/leaf1.cert.pem"))

	testutils.RemoveExistingFile(t, filepath.Join(basedirReal, "out/ca.cert.pem"))

	nowT = nowT.Add(5 * 24 * time.Hour)
	logs, err = testkmgm.Run(t, context.Background(), basedirDummy, yaml.Bytes(),
		[]string{"batch"}, nowT)

	testutils.ExpectErr(t, err, issue.CertStillValidErr{})
	testutils.ExpectFile(t, basedirReal, "out/ca.cert.pem")

	leaf1, err := storage.ReadCertificateFile(filepath.Join(basedirReal, "out/leaf1.cert.pem"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if nowT.Sub(leaf1.NotBefore) < time.Hour {
		t.Errorf("Shouldn't have renewed, but renewed. leaf1.NotBefore=%v", leaf1.NotBefore)
	}

	nowT = nowT.Add(20 * 24 * time.Hour)
	logs, err = testkmgm.Run(t, context.Background(), basedirDummy, yaml.Bytes(),
		[]string{"batch"}, nowT)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "Proceeding with renewal")

	snLeaf2 := serialNumberStringOfCertAtPath(filepath.Join(basedirReal, "out/leaf1.cert.pem"))
	if snLeaf1 == snLeaf2 {
		t.Error("Expected renewal, but not renewed")
	}
}
