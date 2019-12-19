package validate

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func Dir(s string) error {
	s = filepath.Clean(s)
	for s != "." {
		fi, err := os.Stat(s)
		if err != nil {
			if os.IsNotExist(err) {
				s = filepath.Dir(s)
				continue
			}
			return fmt.Errorf("os.Stat(%q): %w", s, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%q is not a dir.", s)
		}

		return nil
	}

	return nil
}

func File(s string) error {
	s = filepath.Clean(s)

	fi, err := os.Stat(s)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os.Stat(%q): %w", s, err)
	}
	if err == nil {
		if fi.IsDir() {
			return fmt.Errorf("New file dest %q is a dir.", s)
		}

		// File exists.
		return nil
	}

	// New File. Check that the parent dir is potentially valid.
	if err := Dir(filepath.Dir(s)); err != nil {
		return err
	}

	return nil
}

// NewFile checks that a file doesn't exist at the specified path and is not a dir.
func NewFile(s string) error {
	s = filepath.Clean(s)

	fi, err := os.Stat(s)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os.Stat(%q): %w", s, err)
	}
	if err == nil {
		if fi.IsDir() {
			return fmt.Errorf("New file dest %q is a dir.", s)
		}
		return fmt.Errorf("File %q already exists.", s)
	}

	if err := Dir(s); err != nil {
		return err
	}

	return nil
}

var placeholderBytes = []byte("placeholder for checking if the file is writable\n")

func MkdirAndCheckWritable(p string) error {
	_, err := os.Stat(p)
	if err == nil {
		return fmt.Errorf("File %q already exists.", p)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os.Stat(%q): %w", p, err)
	}

	dirp := filepath.Dir(p)
	if err := os.MkdirAll(dirp, 0755); err != nil {
		return fmt.Errorf("os.MkdirAll(%q): %w", dirp, err)
	}
	if err := ioutil.WriteFile(p, placeholderBytes, 0400); err != nil {
		return fmt.Errorf("Failed to write to file %q: %w", p, err)
	}
	if err := os.Remove(p); err != nil {
		return fmt.Errorf("Failed to remove placeholder file %q: %w", p, err)
	}

	return nil
}
