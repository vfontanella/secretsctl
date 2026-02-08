package sops

import (
	"fmt"
	"os"
	"strings"
)

func EnsureEncrypted(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if !strings.Contains(string(b), "\nsops:\n") {
		return fmt.Errorf("file is not SOPS-encrypted: %s", path)
	}

	return nil
}
