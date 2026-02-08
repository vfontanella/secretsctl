package sops

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func EncryptFile(plainPath string, ageKey []byte) error {
	if !strings.HasSuffix(plainPath, ".yaml") ||
		strings.HasSuffix(plainPath, ".enc.yaml") {
		return fmt.Errorf("expected plaintext file <name>.yaml")
	}

	encPath := strings.TrimSuffix(plainPath, ".yaml") + ".enc.yaml"

	if _, err := os.Stat(encPath); err == nil {
		return fmt.Errorf("encrypted file already exists: %s", encPath)
	}

	cmd := exec.Command(
		"sops",
		"--encrypt",
		"--output", encPath,
		plainPath,
	)

	cmd.Env = append(
		os.Environ(),
		"SOPS_AGE_KEY="+string(ageKey),
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sops encryption failed: %w", err)
	}

	fmt.Printf("Encrypted %s → %s\n",
		filepath.Base(plainPath),
		filepath.Base(encPath),
	)

	return nil
}
