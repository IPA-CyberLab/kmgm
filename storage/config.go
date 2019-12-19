package storage

import (
	"fmt"
	"os/user"
	"path/filepath"
)

func DefaultStoragePath() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("user.Current: %w", err)
	}
	if u.Uid == "0" {
		return "/var/lib/kmgm", nil
	}
	return filepath.Join(u.HomeDir, ".config", "kmgm"), nil
}
