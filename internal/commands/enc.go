package commands

import (
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"secretsctl/internal/agekms"
	"secretsctl/internal/guard"
)

func EncryptSecret() *cobra.Command {
	return &cobra.Command{
		Use:  "enc <secret>.yaml",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := args[0]
			if err := guard.EnsurePlain(file); err != nil {
				return err
			}

			key, err := agekms.DecryptAGE()
			if err != nil {
				return err
			}

			fifo, err := os.CreateTemp("", "agekey-*")
			if err != nil {
				return err
			}
			defer os.Remove(fifo.Name())

			cmdSops := exec.Command(
				"sops", "-e", file,
			)
			cmdSops.Env = append(os.Environ(),
				"SOPS_AGE_KEY="+string(key),
			)
			cmdSops.Stdout = os.Stdout
			return cmdSops.Run()
		},
	}
}

