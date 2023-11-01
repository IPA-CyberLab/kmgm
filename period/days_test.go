package period

import (
	"testing"
)

func TestDays_UnmarshalFlag(t *testing.T) {
	tests := []struct {
		days    Days
		s       string
		wantErr bool
	}{
		{DaysAuto, "", false},
		{Days(0), "immediately", false},
		{Days(1), "1d", false},
		{Days(365), "1y", false},
		{Days(366), "1y1d", false},
		{Days(3*365 + 35), "3y35d", false},
	}
	for _, tc := range tests {
		t.Run(tc.s, func(t *testing.T) {
			var d Days
			if err := d.UnmarshalFlag(tc.s); (err != nil) != tc.wantErr {
				t.Errorf("Days.UnmarshalFlag() error = %v, wantErr %v", err, tc.wantErr)
			}
			if d != tc.days {
				t.Errorf("Days.UnmarshalFlag() = %v, want %v", d, tc.days)
			}
		})
	}
}
