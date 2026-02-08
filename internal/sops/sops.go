package sops

import (
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
