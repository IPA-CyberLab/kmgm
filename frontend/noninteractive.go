package frontend

import (
	"fmt"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
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

// FIXME[P3]: move this to some other pkg?
func IsNoDefaultSpecifiedInYaml(bs []byte) bool {
	if bs == nil {
		// If no yaml provided, setup relies on cmdline flags only, which
		// user would want to rely on defaults unless --no-default was specified.
		return false
	}

	s := struct {
		NoDefault bool `yaml:"noDefault"`
	}{false}
	if err := yaml.Unmarshal(bs, &s); err != nil {
		return false
	}
	return s.NoDefault
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
