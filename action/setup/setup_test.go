package setup_test

import (
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/setup"
	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/storage"
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

	basedir, err := os.MkdirTemp("", "kmgm_issue_test")
	if err != nil {
		t.Fatalf("ioutil.TempDir: %v", err)
	}

	stor, err := storage.New(basedir)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	fe := &frontend.NonInteractive{
		Logger: zap.L(),
	}

	env, err := action.NewEnvironment(fe, stor)
	if err != nil {
		t.Fatalf("action.NewEnvironment: %v", err)
	}
	env.Frontend = &frontend.NonInteractive{Logger: zap.L()}

	return env, func() {
		os.RemoveAll(basedir)
	}
}

func TestSetup_Default(t *testing.T) {
	env, teardown := testEnv(t)
	t.Cleanup(teardown)

	cfg := setup.DefaultConfig(nil)
	if err := setup.Run(env, cfg); err != nil {
		t.Fatalf("setup.Run: %v", err)
	}
}
