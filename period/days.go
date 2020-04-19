package period

import (
	"fmt"
	"regexp"
	"strconv"
)

type Days uint

func (d Days) String() string {
	if d%365 == 0 {
		return fmt.Sprintf("%dy", d/365)
	}
	return fmt.Sprintf("%dd", d)
}

func (d *Days) UnmarshalFlag(s string) error {
	if ms := reDays.FindStringSubmatch(s); len(ms) > 0 {
		u, err := strconv.ParseUint(ms[1], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to parse days uint %q.", ms[1])
		}
		*d = Days(uint(u))

		return nil
	}
	if ms := reYears.FindStringSubmatch(s); len(ms) > 0 {
		u, err := strconv.ParseUint(ms[1], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to parse years uint %q.", ms[1])
		}
		*d = Days(uint(u) * 365)

		return nil
	}

	return fmt.Errorf("Failed to parse Days %q. Try something like 30d, 1y.", s)
}

func (d *Days) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if err := d.UnmarshalFlag(s); err != nil {
		return err
	}
	return nil
}

var (
	reDays  = regexp.MustCompile(`^(\d+)d$`)
	reYears = regexp.MustCompile(`^(\d+)y$`)
)
