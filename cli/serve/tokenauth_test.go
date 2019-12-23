package serve_test

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/IPA-CyberLab/kmgm/cli/serve"
)

var TestLogger *zap.Logger

func init() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)
	TestLogger = logger
}

func TestTokenFileAuthProvider(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "tokenfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	now := time.Now()

	ta, err := serve.NewTokenFileAuthProvider(tmpfile.Name(), TestLogger)
	if err != nil {
		t.Fatal(err)
	}
	if err := ta.Authenticate("foobar", now); err == nil {
		t.Fatal(err)
	}

	if _, err := tmpfile.Write([]byte("   validtoken\t\t \n")); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	if err := ta.Authenticate("validtoken", now); err != nil {
		t.Fatal(err)
	}
	if err := ta.Authenticate("invalidtoken", now); err == nil {
		t.Fatal(err)
	}
	if err := ta.Authenticate("validtoken", now.Add(20*time.Minute)); err == nil {
		t.Fatal(err)
	}
}
