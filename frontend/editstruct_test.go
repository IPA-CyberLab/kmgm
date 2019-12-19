package frontend_test

import (
	"testing"

	"github.com/IPA-CyberLab/kmgm/frontend"
)

func TestStripErrorText(t *testing.T) {
	testcases := []struct {
		Input    string
		Expected string
	}{
		{"abcd", "abcd"},
		{"", ""},
		{`before
# *** LINES ABOVE WILL BE AUTOMATICALLY DELETED ***
after`,
			"after"},
		{`before
before2
# *** LINES ABOVE WILL BE AUTOMATICALLY DELETED ***
after
after2`,
			"after\nafter2"},
		{`before
# *** LINES ABOVE WILL BE AUTOMATICALLY DELETED ***`,
			""},
	}
	for _, tc := range testcases {
		actual := frontend.StripErrorText(tc.Input)
		if actual != tc.Expected {
			t.Errorf("Expected: %q Actual: %q", tc.Expected, actual)
		}
	}
}
