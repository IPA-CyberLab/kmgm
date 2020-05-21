package storage_test

import (
	"testing"

	"github.com/IPA-CyberLab/kmgm/storage"
)

func TestVerifyProfileName(t *testing.T) {
	testcases := []struct {
		Name  string
		Valid bool
	}{
		{"default", true},
		{"foobar", true},
		{"a", true},
		{"a_b_c", true},
		{"a-b-c", true},
		{".kmgm_server", true},
		{"", false},
		{".", false},
		{"..", false},
		{"./..", false},
		{"日本語", false},
	}

	for _, tc := range testcases {
		err := storage.VerifyProfileName(tc.Name)
		if tc.Valid {
			if err != nil {
				t.Errorf("%q expected to be a valid profile name, got %v", tc.Name, err)
			}
		} else {
			if err == nil {
				t.Errorf("%q expected to be a invalid profile name, got valid", tc.Name)
			}
		}
	}
}
