package issue

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

type ValidityPeriod struct {
	// Days specifies the number of days that the issued cert would be valid for.
	// Days count is ignored if NotAfter is specified to non-zero.
	Days uint

	// NotAfter specifies the timestamp where the cert is considered valid to (inclusive).
	NotAfter time.Time

	// I couldn't find a reasonable use of the user specifying NotBefore % tests.
	// Thus omitting.
}

func (p ValidityPeriod) GetNotAfter(base time.Time) time.Time {
	if !p.NotAfter.IsZero() {
		return p.NotAfter
	}
	return base.Add(time.Duration(p.Days) * 24 * time.Hour)
}

const notAfterLayout = "20060102"

func (p ValidityPeriod) String() string {
	if !p.NotAfter.IsZero() {
		return p.NotAfter.Format(notAfterLayout)
	}
	return fmt.Sprintf("%dd", p.Days)
}

var (
	reDays  = regexp.MustCompile(`^(\d+)d$`)
	reYears = regexp.MustCompile(`^(\d+)y$`)
)

func (p *ValidityPeriod) UnmarshalFlag(s string) error {
	if ms := reDays.FindStringSubmatch(s); len(ms) > 0 {
		u, err := strconv.ParseUint(ms[1], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to parse days uint %q.", ms[1])
		}
		p.Days = uint(u)

		return nil
	}
	if ms := reYears.FindStringSubmatch(s); len(ms) > 0 {
		u, err := strconv.ParseUint(ms[1], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to parse years uint %q.", ms[1])
		}
		p.Days = uint(u) * 365

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

var FarFuture = ValidityPeriod{
	Days: 0,

	// RFC5280 4.1.2.5 says we should use 99991231235959Z, for the certs which
	// never expire but some implementation have issues handling the date.
	// We pick 2099-12-31 for the timestamp of a reasonably far future.
	NotAfter: time.Date(2099, 12, 31, 23, 59, 0, 0, time.UTC),
}
