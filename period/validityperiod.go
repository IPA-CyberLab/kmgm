package period

import (
	"fmt"
	"strings"
	"time"
)

type ValidityPeriod struct {
	// Days specifies the number of days that the issued cert would be valid for.
	// Days count is ignored if NotAfter is specified to non-zero.
	Days

	// NotAfter specifies the timestamp where the cert is considered valid to (inclusive).
	NotAfter time.Time

	// I couldn't find a reasonable use of the user specifying NotBefore % tests.
	// Thus omitting.
}

var FarFuture = ValidityPeriod{
	Days: 0,

	// RFC5280 4.1.2.5 says we should use 99991231235959Z, for the certs which
	// never expire but some implementation have issues handling the date.
	// We pick 2099-12-31 for the timestamp of a reasonably far future.
	NotAfter: time.Date(2099, 12, 31, 23, 59, 0, 0, time.UTC),
}

func (p ValidityPeriod) GetNotAfter(base time.Time) time.Time {
	if !p.NotAfter.IsZero() {
		return p.NotAfter
	}
	return base.Add(time.Duration(p.Days) * 24 * time.Hour)
}

const notAfterLayout = "20060102"

func (p ValidityPeriod) String() string {
	if p.NotAfter.Equal(FarFuture.NotAfter) {
		return "farfuture"
	}
	if !p.NotAfter.IsZero() {
		return p.NotAfter.Format(notAfterLayout)
	}
	return p.Days.String()
}

func (p *ValidityPeriod) UnmarshalFlag(s string) error {
	if strings.ToLower(s) == "farfuture" {
		*p = FarFuture
		return nil
	}
	if err := p.Days.UnmarshalFlag(s); err == nil {
		return nil
	}
	if t, err := time.ParseInLocation(notAfterLayout, s, time.Local); err == nil {
		p.NotAfter = t
		return nil
	}

	return fmt.Errorf("Failed to parse ValidityPeriod %q. Try something like 30d, 1y, or 20220530.", s)
}

func (p *ValidityPeriod) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if err := p.UnmarshalFlag(s); err != nil {
		return err
	}
	return nil
}
