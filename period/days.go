package period

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const immediatelyToken = "immediately"

type Days int

const (
	DaysUnset       Days = -1
	DaysImmediately Days = 0
)

func (d Days) String() string {
	switch d {
	case DaysUnset:
		return "<unset>"
	case 0:
		return immediatelyToken
	default:
	}

	left := d

	years := left / 365
	left -= years * 365
	if years > 0 {
		return fmt.Sprintf("%dy%dd", years, left)
	} else {
		return fmt.Sprintf("%dd", left)
	}
}

var (
	reYears = regexp.MustCompile(`^(\d+)y(.*)`)
	reDays  = regexp.MustCompile(`^(\d+)d$`)
)

func (d *Days) UnmarshalFlag(s string) error {
	switch s {
	case "", "<unset>":
		*d = DaysUnset
		return nil
	case immediatelyToken:
		*d = Days(0)
		return nil
	default:
	}

	*d = Days(0)
	left := s

	if ms := reYears.FindStringSubmatch(left); len(ms) > 0 {
		u, err := strconv.ParseUint(ms[1], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to parse years uint %q.", ms[1])
		}
		*d += Days(uint(u) * 365)
		left = ms[2]
		if left == "" {
			return nil
		}
	}

	if ms := reDays.FindStringSubmatch(left); len(ms) > 0 {
		u, err := strconv.ParseUint(ms[1], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to parse days uint %q.", ms[1])
		}
		*d += Days(uint(u))

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

func (d Days) ToDuration() time.Duration {
	return time.Duration(d) * 24 * time.Hour
}
