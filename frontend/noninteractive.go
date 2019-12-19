package frontend

import "go.uber.org/zap"

type NonInteractive struct {
	Content string
	Logger  *zap.Logger
}

var _ = Frontend(&NonInteractive{})

func (fe *NonInteractive) Confirm(q string) error {
	slog := fe.Logger.Sugar()
	slog.Infof("%q -> yes [noninteractive]", q)
	return nil
}

func (fe *NonInteractive) EditText(beforeEdit string, validator func(string) (string, error)) (string, error) {
	slog := fe.Logger.Sugar()

	if fe.Content != "" {
		beforeEdit = fe.Content
	}

	txt, err := validator(beforeEdit)
	if err != nil {
		return txt, err
	}

	slog.Infof("[noninteractive] proceeding with %q", txt)

	return txt, nil
}

func (fe *NonInteractive) Configure(items []ConfigItem) error {
	slog := fe.Logger.Sugar()
	for _, i := range items {
		slog.Infof("[noninteractive] %s = %q.", i.Label, *i.Value)
	}

	return nil
}
