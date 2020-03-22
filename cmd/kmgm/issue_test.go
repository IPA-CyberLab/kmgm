package main_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	main "github.com/IPA-CyberLab/kmgm/cmd/kmgm"
)

func TestIssue(t *testing.T) {
	app := main.NewApp()

	zobs, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(zobs)
	app.Metadata = make(map[string]interface{})
	app.Metadata["Logger"] = logger

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	app.Writer = &stdoutBuf
	app.ErrWriter = &stderrBuf
	tmpfile, err := ioutil.TempFile("", "config.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	yaml := []byte(`
noDefault: true
`)

	if _, err := tmpfile.Write(yaml); err != nil {
		t.Fatal(err)
	}
	// We need Close() here since we read the tmpfile later in the test.
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	if err := app.Run([]string{"kmgm", "--config", tmpfile.Name(), "issue"}); err != nil {
		t.Errorf("app err: %v", err)
	}

	t.Logf("stdout: %s", stdoutBuf.String())
	t.Logf("stderr: %s", stderrBuf.String())
	t.Logf("%+v", logs.TakeAll())
}
