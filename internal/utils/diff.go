package utils

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
)

func DiffEncryptedFile(encPath string, ageKey []byte) error {
	cmd := exec.Command("sops", "-d", encPath)
	cmd.Env = append(
		os.Environ(),
		"SOPS_AGE_KEY="+string(ageKey),
	)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("diff failed (cannot decrypt): %w", err)
	}

	sum := sha256.Sum256(out.Bytes())

	fmt.Printf(
		"Decrypted content SHA-256 (audit only): %x\n",
		sum,
	)

	return nil
}
