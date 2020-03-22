package main_test

import (
	"bytes"
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
)

func prepareBasedir(t *testing.T) (string, func()) {
	t.Helper()

	basedir, err := ioutil.TempDir("", "kmgm-testdir-*")
	if err != nil {
		t.Fatal(err)
	}

	return basedir, func() { os.RemoveAll(basedir) }
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

func TestIssue_NoCA(t *testing.T) {
	basedir, teardown := prepareBasedir(t)
	t.Cleanup(teardown)

	yaml := []byte(`
noDefault: true
`)

	logs, err := runKmgm(t, basedir, yaml, []string{"issue"})
	expectErr(t, err, setup.ErrCantRunInteractiveCaSetup)
	_ = logs //expectLogMessage(t, logs, "")
}
