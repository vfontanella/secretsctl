package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"secretsctl/internal/agekms"
	"secretsctl/internal/sops"
	"strings"

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

			// Guard 1: encrypted AGE key already exists → verify only
			if _, err := os.Stat(agekms.EncryptedKey); err == nil {
				key, err := agekms.DecryptAGE()
				if err != nil {
					return err
				}

				pub, err := extractAgePublicKey(key)
				if err != nil {
					return err
				}

				if err := agekms.VerifyFingerprint(pub); err != nil {
					return err
				}

				fmt.Println("AGE key verified (encrypted key + fingerprint match)")
				return nil
			}

			// Guard 2: fingerprint exists but encrypted key does not → fail
			if _, err := os.Stat(agekms.FingerprintFile); err == nil {
				return fmt.Errorf(
					"fingerprint exists but encrypted AGE key is missing; refusing to regenerate",
				)
			}

			// Fresh bootstrap: generate AGE key in memory
			cmdKeygen := exec.Command("age-keygen")
			cmdKeygen.Stderr = os.Stderr

			key, err := cmdKeygen.Output()
			if err != nil {
				return fmt.Errorf("age-keygen failed: %w", err)
			}

			pub, err := extractAgePublicKey(key)
			if err != nil {
				return err
			}

			sum := sha256.Sum256([]byte(pub))
			if err := os.WriteFile(
				agekms.FingerprintFile,
				[]byte(fmt.Sprintf("%x", sum)),
				0600,
			); err != nil {
				return err
			}

			if err := agekms.EncryptAGE(key); err != nil {
				return err
			}

			if err := sops.WriteConfig(pub); err != nil {
				return err
			}

			fmt.Println("AGE key generated, fingerprinted, encrypted, and .sops.yaml created")
			return nil

		},
	}
}

/* ---------------- STUB COMMANDS (compile-safe) ---------------- */

func encryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enc <secret>.yaml",
		Short: "Encrypt a plaintext secret using SOPS + AGE",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plain := args[0]

			// Filename guard
			if filepath.Ext(plain) != ".yaml" {
				return fmt.Errorf("plaintext secret must be a .yaml file")
			}
			if strings.HasSuffix(plain, ".enc.yaml") {
				return fmt.Errorf("file is already encrypted")
			}

			enc := strings.TrimSuffix(plain, ".yaml") + ".enc.yaml"

			// Refuse overwrite
			if _, err := os.Stat(enc); err == nil {
				return fmt.Errorf("encrypted secret already exists: %s", enc)
			}

			// Ensure plaintext exists
			if _, err := os.Stat(plain); err != nil {
				return fmt.Errorf("plaintext secret not found: %s", plain)
			}

			// Ensure AGE key exists
			if _, err := os.Stat(agekms.EncryptedKey); err != nil {
				return errors.New("AGE key not bootstrapped; run `secretsctl bootstrap`")
			}

			// Decrypt AGE key (memory only)
			ageKey, err := agekms.DecryptAGE()
			if err != nil {
				return err
			}

			// Run SOPS
			cmdSops := exec.Command(
				"sops",
				"--encrypt",
				"--output", enc,
				plain,
			)

			cmdSops.Env = append(
				os.Environ(),
				"SOPS_AGE_KEY="+string(ageKey),
			)

			cmdSops.Stdout = os.Stdout
			cmdSops.Stderr = os.Stderr

			if err := cmdSops.Run(); err != nil {
				return fmt.Errorf("sops encryption failed: %w", err)
			}

			fmt.Printf("Encrypted %s → %s\n", plain, enc)
			return nil
		},
	}
}

func decryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dec <secret>.enc.yaml",
		Short: "Decrypt a SOPS-encrypted secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return sops.DecryptFile(args[0])
		},
	}
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <secret>.enc.yaml",
		Short: "Validate encrypted secret (stub)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("validate not implemented yet")
		},
	}
}

func diffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <secret>.enc.yaml",
		Short: "Diff encrypted secret (stub)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("diff not implemented yet")
		},
	}
}

func extractAgePublicKey(privateKey []byte) (string, error) {
	lines := strings.Split(string(privateKey), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "# public key:") {
			return strings.TrimSpace(
				strings.TrimPrefix(line, "# public key:"),
			), nil
		}
	}
	return "", fmt.Errorf("public key not found in AGE key material")
}
