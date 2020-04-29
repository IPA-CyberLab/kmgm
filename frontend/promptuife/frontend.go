package promptuife

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/manifoldco/promptui"

	"github.com/IPA-CyberLab/kmgm/frontend"
)

var PromptTemplate = &promptui.PromptTemplates{
	Success: `{{ . | bold }}{{ ":" | bold }} `,
}

type Frontend struct{}

var _ = frontend.Frontend(Frontend{})

func (Frontend) Confirm(q string) error {
	// promptui automatically append '?' at the end of |IsConfirm| |Label|.
	// Avoid printing double '?'s at the end.
	q = strings.TrimRight(q, "?")

	p := promptui.Prompt{
		Label:     q,
		IsConfirm: true,
		Default:   "y",
		Templates: PromptTemplate,
	}
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}

var ErrAbortEdit = errors.New("frontend: User declined to correct error")

func stripTrailingWhitespace(s string) string {
	return strings.TrimRight(s, " \n")
}

func (fe Frontend) IsInteractive() bool { return true }

func (fe Frontend) EditText(beforeEdit string, validator func(string) (string, error)) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("user.Current: %w", err)
	}

	// Use /tmp if root?
	tmppath := filepath.Join(u.HomeDir, ".kmgm_input.yaml")

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}

	for {
		if err := ioutil.WriteFile(tmppath, []byte(beforeEdit), 0600); err != nil {
			return "", fmt.Errorf("Failed to write to tmpfile %q: %w", tmppath, err)
		}

		c := exec.Command(editor, tmppath)
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return "", fmt.Errorf("Failed to run editor %q: %w", editor, err)
		}

		bs, err := ioutil.ReadFile(tmppath)
		if err != nil {
			return "", fmt.Errorf("Failed to read afterEdit result %q: %w", tmppath, err)
		}
		afterEdit := string(bs)

		suggestion, err := validator(afterEdit)
		if err == nil {
			break
		}
		fmt.Printf("Invalid entry: %v\n", err)
		if stripTrailingWhitespace(afterEdit) == stripTrailingWhitespace(beforeEdit) {
			if err := fe.Confirm("Continue edit"); err != nil {
				return "", ErrAbortEdit
			}
		}

		beforeEdit = suggestion
	}

	fmt.Println("Validator passed :)")
	return beforeEdit, nil
}

func myBlockCursor(input []rune) []rune {
	return []rune(fmt.Sprintf("\033[7m%s\033[0m", string(input)))
}

func (fe Frontend) Configure(items []frontend.ConfigItem) error {
	for _, i := range items {
		var err error
		p := promptui.Prompt{
			Label:     i.Label,
			Validate:  i.Validate,
			Default:   *i.Value,
			Templates: PromptTemplate,
			AllowEdit: true,
			Pointer:   myBlockCursor,
		}
		*i.Value, err = p.Run()
		if err != nil {
			return fmt.Errorf("prompt %s failed: %w", i.Label, err)
		}
	}
	return nil
}
