package sops

import (
	"fmt"
	"os"
)

const SopsConfigFile = ".sops.yaml"

// WriteConfig creates a .sops.yaml file using the provided AGE public key.
// It refuses to overwrite an existing config.
func WriteConfig(agePublicKey string) error {
	if _, err := os.Stat(SopsConfigFile); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite", SopsConfigFile)
	}

	content := fmt.Sprintf(
		`creation_rules:
  			- path_regex: .*\.yaml$
    		  encrypted_regex: '^(data|stringData)$'
    		age:
      		- %s
			  `, agePublicKey)

	if err := os.WriteFile(SopsConfigFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", SopsConfigFile, err)
	}

	fmt.Println("Created .sops.yaml")
	return nil
}
