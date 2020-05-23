package pubkeyhash

import "fmt"

type FormatType int

const (
	FormatFull FormatType = iota
	FormatHashOnly
)

func FormatTypeFromString(s string) (FormatType, error) {
	switch s {
	case "full":
		return FormatFull, nil
	case "hashonly":
		return FormatHashOnly, nil
	default:
		return FormatFull, fmt.Errorf("Unknown format %q.", s)
	}
}

func (ft FormatType) ShouldOutputLabel() bool {
	switch ft {
	case FormatFull:
		return true
	default:
		return false
	}
}
