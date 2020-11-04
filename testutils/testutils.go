package testutils

import (
	"errors"
	"io/ioutil"
	"os"
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

	basedir, err := ioutil.TempDir("", "kmgm-testdir-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(basedir) })

	return basedir
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
