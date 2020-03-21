package frontend

import (
	"fmt"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

type NonInteractive struct {
	Logger     *zap.Logger
	ConfigText string
}

var _ = Frontend(&NonInteractive{})

func (fe *NonInteractive) Confirm(q string) error {
	slog := fe.Logger.Sugar()
	slog.Infof("%q -> yes [noninteractive]", q)
	return nil
}

// FIXME[P2] Test me
func (fe *NonInteractive) ShouldLoadDefaults() bool {
	s := struct {
		NoDefault bool `yaml:"noDefault"`
	}{false}
	if err := yaml.Unmarshal([]byte(fe.ConfigText), &s); err != nil {
		return false
	}
	return !s.NoDefault
}

func (fe *NonInteractive) EditText(beforeEdit string, validator func(string) (string, error)) (string, error) {
	slog := fe.Logger.Sugar()

	txt, err := validator(fe.ConfigText)
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
