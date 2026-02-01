package sops

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func DecryptFile(encPath string) error {
	if !strings.HasSuffix(encPath, ".enc.yaml") {
		return fmt.Errorf("expected encrypted file <name>.enc.yaml")
	}

	plainPath := strings.TrimSuffix(encPath, ".enc.yaml") + ".yaml"

	if _, err := os.Stat(plainPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing plaintext file: %s", plainPath)
	}

	if err := ensureSopsEncrypted(encPath); err != nil {
		return err
	}

	cmd := exec.Command("sops", "-d", encPath)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("sops decryption failed: %w", err)
	}

	if err := os.WriteFile(plainPath, out, 0600); err != nil {
		return err
	}

	fmt.Printf("Decrypted %s → %s\n", filepath.Base(encPath), filepath.Base(plainPath))
	return nil
}
