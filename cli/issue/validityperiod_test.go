package issue_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/cli/issue"
)

func TestValidityPeriod_UnmarshalFlag(t *testing.T) {
	testcases := []struct {
		Expected issue.ValidityPeriod
		Target   string
	}{
		{issue.ValidityPeriod{Days: 123}, "123d"},
		{issue.ValidityPeriod{Days: 245}, "245d"},
		{issue.ValidityPeriod{Days: 3650}, "10y"},
		{issue.ValidityPeriod{NotAfter: time.Date(2019, 6, 1, 0, 0, 0, 0, time.Local)}, "20190601"},
	}

	for _, tc := range testcases {
		var p issue.ValidityPeriod
		if err := p.UnmarshalFlag(tc.Target); err != nil {
			t.Errorf("Failed to parse %q: %v", tc.Target, err)
		}
		if !reflect.DeepEqual(tc.Expected, p) {
			t.Errorf("Parse %q failed. Expected %+v, Actual %+v", tc.Target, tc.Expected, p)
		}
	}
}
