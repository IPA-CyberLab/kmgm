package period_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/period"
)

var testcases = []struct {
	Validity period.ValidityPeriod
	String   string
}{
	{period.ValidityPeriod{Days: period.DaysAuto}, "auto"},
	{period.ValidityPeriod{Days: 0}, "immediately"},
	{period.ValidityPeriod{Days: 123}, "123d"},
	{period.ValidityPeriod{Days: 245}, "245d"},
	{period.ValidityPeriod{Days: 3650}, "10y0d"},
	{period.ValidityPeriod{NotAfter: time.Date(2019, 6, 1, 0, 0, 0, 0, time.Local)}, "20190601"},
	{period.FarFuture, "farfuture"},
}

func TestValidityPeriod_UnmarshalFlag(t *testing.T) {
	for _, tc := range testcases {
		var p period.ValidityPeriod
		if err := p.UnmarshalFlag(tc.String); err != nil {
			t.Errorf("Failed to parse %q: %v", tc.String, err)
		}
		if !reflect.DeepEqual(tc.Validity, p) {
			t.Errorf("Parse %q failed. Expected %+v, Actual %+v", tc.String, tc.Validity, p)
		}
	}
}

func TestValidityPeriod_String(t *testing.T) {
	for _, tc := range testcases {
		s := tc.Validity.String()
		if s != tc.String {
			t.Errorf("Expected %q but got %q", tc.String, s)
		}
	}
}
