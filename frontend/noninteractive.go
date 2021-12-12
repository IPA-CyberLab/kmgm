package frontend

import (
	"fmt"

	"go.uber.org/zap"
)

type NonInteractive struct {
	Logger *zap.Logger
}

var _ = Frontend(&NonInteractive{})

func (fe *NonInteractive) Confirm(q string) error {
	slog := fe.Logger.Sugar()
	slog.Infof("%q -> yes [noninteractive]", q)
	return nil
}

func (fe *NonInteractive) IsInteractive() bool { return false }

func (fe *NonInteractive) EditText(beforeEdit string, validator func(string) (string, error)) (string, error) {
	slog := fe.Logger.Sugar()

	txt, err := validator(beforeEdit)
	if err != nil {
		slog.Debugf("[noninteractive] Parsed input was:\n%s", txt)
		return txt, fmt.Errorf("Validate input failed: %w", err)
	}

	slog.Infof("[noninteractive] proceeding with:\n%s", txt)

	return txt, nil
}

func (fe *NonInteractive) Configure(items []ConfigItem) error {
	slog := fe.Logger.Sugar()
	for _, i := range items {
		slog.Infof("[noninteractive] %s = %q.", i.Label, *i.Value)
	}

	return nil
}
