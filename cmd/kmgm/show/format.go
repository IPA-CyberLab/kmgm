package show

import "fmt"

type FormatType int

const (
	FormatFull FormatType = iota
	FormatPEM
)

func (t FormatType) String() string {
	switch t {
	case FormatFull:
		return "full"
	case FormatPEM:
		return "pem"
	default:
		return fmt.Sprintf("unknown_formattype_%d", int(t))
	}
}

func FormatTypeFromString(s string) (FormatType, error) {
	switch s {
	case "full":
		return FormatFull, nil
	case "pem":
		return FormatPEM, nil
	default:
		return FormatFull, fmt.Errorf("Unknown format %q.", s)
	}
}

func (t FormatType) ShouldOutputInfo() bool {
	switch t {
	case FormatFull:
		return true
	default:
		return false
	}
}

func (t FormatType) ShouldOutputPEM() bool {
	switch t {
	case FormatFull, FormatPEM:
		return true
	default:
		return false
	}
}
