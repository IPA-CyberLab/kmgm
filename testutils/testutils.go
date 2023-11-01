package testutils

import (
	"errors"
	"os"
	"os/exec"
	"path"
	"regexp"
	"testing"

	"github.com/IPA-CyberLab/kmgm/domainname"
	"github.com/IPA-CyberLab/kmgm/ipapi"
	"go.uber.org/zap/zaptest/observer"
)

func init() {
	ipapi.MockResult = &ipapi.Result{
		RegionName:  "California",
		CountryCode: "US",
	}

	domainname.MockResult = "host.example"
}

func PrepareBasedir(t *testing.T) string {
	t.Helper()

	basedir, err := os.MkdirTemp("", "kmgm-testdir-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(basedir) })

	return basedir
}

func ExpectEmptyDir(t *testing.T, basedirDummy string) {
	t.Helper()

	f, err := os.Open(basedirDummy)
	if err != nil {
		t.Fatal(err)
	}
	des, err := f.ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		t.Error("Found unexpected file:", de.Name())
	}
}

func ExpectFile(t *testing.T, basedir string, relpath string) {
	t.Helper()

	filepath := path.Join(basedir, relpath)

	if _, err := os.Stat(filepath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Unexpected error when Stat(%q): %v", filepath, err)
		}
		t.Errorf("File %s does not exist.", filepath)

		cmd := exec.Command("tree", basedir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Error running tree command: %v", err)
		}
		t.Logf("Directory structure of %s:\n%s", basedir, out)
		return
	}
}

func ExpectFileNotExist(t *testing.T, basedir, relpath string) {
	t.Helper()

	filepath := path.Join(basedir, relpath)

	if _, err := os.Stat(filepath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Errorf("Unexpected error when Stat(%q): %v", filepath, err)
		return
	}
	t.Errorf("File %s exists while it shouldn't.", filepath)
}

func ExpectLogMessage(t *testing.T, logs *observer.ObservedLogs, expectedRE string) {
	t.Helper()

	re := regexp.MustCompile(expectedRE)
	for _, l := range logs.All() {
		if re.MatchString(l.Message) {
			return
		}
	}

	t.Errorf("Could not find a log line that matches %s", expectedRE)
}

func ExpectErrMessage(t *testing.T, err error, expectedRE string) {
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

func ExpectErr(t *testing.T, actual, expected error) {
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

func RemoveExistingFile(t *testing.T, fpath string) {
	if err := os.Remove(fpath); err != nil {
		t.Errorf("os.Remove(%q) failed: %v", fpath, err)
	}
}
