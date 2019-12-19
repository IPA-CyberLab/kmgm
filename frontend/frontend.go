package frontend

type ConfigItem struct {
	Label    string
	Validate func(string) error
	Value    *string
}

type Frontend interface {
	Confirm(question string) error
	EditText(template string, validator func(string) (string, error)) (edited string, err error)
	Configure([]ConfigItem) error
}
