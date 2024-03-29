package testkmgm

import (
	"bytes"
	"context"
	"io/ioutil"
	mrand "math/rand"
	"os"
	"testing"
	"time"

	"github.com/urfave/cli/v2"
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

type mockClock struct {
	t time.Time
}

func (c mockClock) Now() time.Time {
	return c.t
}

func (c mockClock) NewTicker(duration time.Duration) *time.Ticker {
	panic("not implemented")
	return nil
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
	if err != nil {
		panic(err)
	}
	env.Frontend = &frontend.NonInteractive{Logger: zap.L()}
	env.NowImpl = mockNowImpl(mockNow)
	env.Randr = MrandReader{}
	env.PregenKeySupplier = GetPregenKey

	return env
}

type MrandReader struct{}

func (MrandReader) Read(p []byte) (int, error) {
	return mrand.Read(p)
}

func Run(t *testing.T, ctx context.Context, basedir string, configYaml []byte, args []string, mockNow time.Time) (*observer.ObservedLogs, error) {
	t.Helper()

	a := app.New()

	zobs, logs := observer.New(zapcore.DebugLevel)

	logger := zap.New(zobs, zap.WithClock(mockClock{mockNow}))
	a.Metadata["Logger"] = logger
	a.Metadata["NowImpl"] = mockNowImpl(mockNow)
	a.Metadata["Randr"] = MrandReader{}
	a.Metadata["PregenKeySupplier"] = GetPregenKey

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	a.Writer = &stdoutBuf
	a.ErrWriter = &stderrBuf

	// replace `ExitErrHandler` to avoid exiting the test process.
	a.ExitErrHandler = func(cCtx *cli.Context, err error) {}

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
		t.Logf("🔒 %s", l.Message)
	}
	return logs, err
}
