package main

import (
	"errors"
	"fmt"
	"os"

	"secretsctl/internal/agekms"
	"secretsctl/internal/sops"
	"secretsctl/internal/utils"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "secretsctl",
		Short: "AGE + SOPS + AWS KMS secrets manager",
	}

	root.AddCommand(
		bootstrapCmd(),
		encryptCmd(),
		decryptCmd(),
		validateCmd(),
		diffCmd(),
		doctorCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

/* ---------------- BOOTSTRAP ---------------- */

func bootstrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bootstrap",
		Short: "Initialize or verify AGE key encrypted with KMS",
		RunE: func(cmd *cobra.Command, args []string) error {

			pub, err := agekms.Bootstrap()
			if err != nil {
				return err
			}

			// Create .sops.yaml if missing
			if err := sops.WriteConfig(pub); err != nil {
				// Non-fatal if already exists
				fmt.Println(err)
			}

			return nil
		},
	}
}

/* ---------------- ENCRYPT ---------------- */

func encryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enc <secret>.yaml",
		Short: "Encrypt a plaintext secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if _, err := os.Stat(agekms.EncryptedKey); err != nil {
				return errors.New("AGE key not bootstrapped")
			}

			key, err := agekms.DecryptAGE()
			if err != nil {
				return err
			}

			return sops.EncryptFile(args[0], key)
		},
	}
}

/* ---------------- DECRYPT ---------------- */

func decryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dec <secret>.enc.yaml",
		Short: "Decrypt an encrypted secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			key, err := agekms.DecryptAGE()
			if err != nil {
				return err
			}

			return sops.DecryptFile(args[0], key)
		},
	}
}

/* ---------------- VALIDATE ---------------- */

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <secret>.enc.yaml",
		Short: "Validate encrypted secret access",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			key, err := agekms.DecryptAGE()
			if err != nil {
				return err
			}

			return utils.ValidateEncryptedFile(args[0], key)
		},
	}
}

/* ---------------- DIFF ---------------- */

func diffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <secret>.enc.yaml",
		Short: "Audit encrypted secret (hash only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			key, err := agekms.DecryptAGE()
			if err != nil {
				return err
			}

			return utils.DiffEncryptedFile(args[0], key)
		},
	}
}

/* ---------------- DOCTOR ---------------- */

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check environment and dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			return utils.DoctorCheck()
		},
	}
}
