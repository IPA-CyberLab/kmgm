package main_test

import (
	"bytes"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	main "github.com/IPA-CyberLab/kmgm/cmd/kmgm"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/setup"
	"github.com/IPA-CyberLab/kmgm/ipapi"
	"github.com/IPA-CyberLab/kmgm/storage"
)

var noDefaultYaml = []byte(`
noDefault: true
`)

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

func readCASubject(t *testing.T, basedir string) pkix.Name {
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

	return cacert.Subject
}

func runKmgm(t *testing.T, basedir string, configYaml []byte, args []string) (*observer.ObservedLogs, error) {
	t.Helper()

	app := main.NewApp()

	zobs, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(zobs)
	app.Metadata = make(map[string]interface{})
	app.Metadata["Logger"] = logger

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
	err := app.Run(as)

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

	logs, err := runKmgm(t, basedir, nil, []string{"setup"})
	expectErr(t, err, nil)
	expectLogMessage(t, logs, "CA setup successfully completed")
}

func TestSetup_EmptyConfig(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	spaces := []byte(" \t\n")
	logs, err := runKmgm(t, basedir, spaces, []string{"setup"})
	expectErrMessage(t, err, `was empty\.$`)
	_ = logs
}

func TestSetup_Default(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	yaml := []byte(`
noDefault: false
`)

	logs, err := runKmgm(t, basedir, yaml, []string{"setup"})
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
`)

	logs, err := runKmgm(t, basedir, yaml, []string{"setup"})
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
`)

	logs, err := runKmgm(t, basedir, yaml, []string{"setup"})
	// FIXME[P1]: Better error message
	expectErrMessage(t, err, "Unknown key type: any")
	_ = logs
}

func TestSetup_Flags(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	logs, err := runKmgm(t, basedir, nil, []string{"setup", "--country", "JP"})
	expectErr(t, err, nil)
	_ = logs

	s := readCASubject(t, basedir)

	if s.CommonName == "" {
		t.Errorf("Expected non-empty CommonName, but got empty")
	}

	if s.Province[0] != "California" {
		t.Errorf("Wront Province %+v", s.Province)
	}

	if s.Country[0] != "JP" {
		t.Errorf("wrong country %q", s.Country[0])
	}
}

func TestSetup_NoDefault_Flags(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	logs, err := runKmgm(t, basedir, nil, []string{"--no-default", "setup", "--country", "JP", "--key-type", "rsa"})
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

	logs, err := runKmgm(t, basedir, nil, []string{"issue"})
	expectErr(t, err, setup.ErrCantRunInteractiveCaSetup)
	_ = logs //expectLogMessage(t, logs, "")
}
