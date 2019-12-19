package validate

import (
	"fmt"
)

/*
[X.520] ITU-T Recommendation X.520 (2005) | ISO/IEC 9594-6:2005,
        Information technology - Open Systems Interconnection -
        The Directory: Selected attribute types.
*/

func PKIXElement(ub int) func(s string) error {
	return func(s string) error {
		if len(s) > ub {
			return fmt.Errorf("string longer than its allowed length %d.", ub)
		}
		for _, r := range s {
			// FIXME[P4]: make more strict
			if r > 0x7f {
				return fmt.Errorf("Rune '%c' is not allowed.", r)
			}
		}
		return nil
	}
}
