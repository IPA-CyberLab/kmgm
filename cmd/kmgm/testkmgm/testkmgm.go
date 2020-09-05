package testkmgm

import (
	"bytes"
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/app"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/storage"
)

var NowDefault = time.Date(2020, time.March, 1, 0, 0, 0, 0, time.UTC)

func mockNowImpl(t time.Time) func() time.Time {
	return func() time.Time {
		return t
	}
}

func Env(t *testing.T, basedir string, mockNow time.Time) *action.Environment {
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

func Run(t *testing.T, ctx context.Context, basedir string, configYaml []byte, args []string, mockNow time.Time) (*observer.ObservedLogs, error) {
	t.Helper()

	a := app.New()

	zobs, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(zobs)
	a.Metadata = make(map[string]interface{})
	a.Metadata["Logger"] = logger
	a.Metadata["NowImpl"] = mockNowImpl(mockNow)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	a.Writer = &stdoutBuf
	a.ErrWriter = &stderrBuf

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
	err := a.RunContext(ctx, as)

	t.Logf("stdout: %s", stdoutBuf.String())
	t.Logf("stderr: %s", stderrBuf.String())
	for _, l := range logs.All() {
		t.Logf("%+v", l)
	}
	return logs, err
}
