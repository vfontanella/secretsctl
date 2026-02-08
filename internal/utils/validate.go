package utils

import (
	"fmt"
	"os"
	"os/exec"
)

func ValidateEncryptedFile(encPath string, ageKey []byte) error {
	cmd := exec.Command("sops", "-d", encPath)
	cmd.Env = append(
		os.Environ(),
		"SOPS_AGE_KEY="+string(ageKey),
	)

	cmd.Stdout = nil
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	return nil
}
