package validityperiod_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/validityperiod"
)

var testcases = []struct {
	Validity validityperiod.ValidityPeriod
	String   string
}{
	{validityperiod.ValidityPeriod{Days: 123}, "123d"},
	{validityperiod.ValidityPeriod{Days: 245}, "245d"},
	{validityperiod.ValidityPeriod{Days: 3650}, "10y"},
	{validityperiod.ValidityPeriod{NotAfter: time.Date(2019, 6, 1, 0, 0, 0, 0, time.Local)}, "20190601"},
	{validityperiod.FarFuture, "farfuture"},
}

func TestValidityPeriod_UnmarshalFlag(t *testing.T) {
	for _, tc := range testcases {
		var p validityperiod.ValidityPeriod
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
