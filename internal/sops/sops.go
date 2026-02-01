package sops

import (
	"fmt"
	"os"
	"os/exec"
)

func Run(args []string, ageKey []byte) error {
	cmd := exec.Command("sops", args...)
	cmd.Env = append(os.Environ(),
		"SOPS_AGE_KEY="+string(ageKey),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func WriteConfig(agePublicKey string) error {
	const path = ".sops.yaml"

	// Refuse to overwrite
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf(".sops.yaml already exists; refusing to overwrite")
	}

	content := fmt.Sprintf(
		`creation_rules:
  - path_regex: .*\.yaml$
    encrypted_regex: '^(data|stringData)$'
    age:
      - %s
`, agePublicKey)

	return os.WriteFile(path, []byte(content), 0600)
}
