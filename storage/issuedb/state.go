package issuedb

import (
	"encoding/json"
	"errors"
	"fmt"
)

type State int

const (
	IssueInProgress State = iota
	ActiveCertificate
)

func (s State) String() string {
	switch s {
	case IssueInProgress:
		return "issue_in_progress"
	case ActiveCertificate:
		return "active"
	}
	return fmt.Sprintf("unknown_state_%d", s)
}

func (s State) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *State) UnmarshalJSON(bs []byte) error {
	var str string
	if err := json.Unmarshal(bs, &str); err != nil {
		return fmt.Errorf("Unmarshal issuedb.State string: %w", err)
	}

	switch str {
	case "issue_in_progress":
		*s = IssueInProgress
		return nil
	case "active":
		*s = ActiveCertificate
		return nil
	default:
		return fmt.Errorf("Unknown State %q", str)
	}
}

func validateStateTransfer(current, next State) error {
	switch current {
	case IssueInProgress:
		if next == ActiveCertificate {
			return nil
		}
		return fmt.Errorf("Invalid state transfer issue_in_progress -> %v.", next)

	case ActiveCertificate:
		return errors.New("No valid state transfer from ActiveCertificate state.")

	default:
		return fmt.Errorf("Unknown current state: %v", current)
	}
}
