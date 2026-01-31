package guard

import "fmt"

func Plain(name string) error {
	if len(name) < 6 || name[len(name)-5:] != ".yaml" {
		return fmt.Errorf("invalid plaintext secret name")
	}
	if len(name) > 9 && name[len(name)-9:] == ".enc.yaml" {
		return fmt.Errorf("already encrypted")
	}
	return nil
}

func Encrypted(name string) error {
	if len(name) < 9 || name[len(name)-9:] != ".enc.yaml" {
		return fmt.Errorf("not an encrypted secret")
	}
	return nil
}

