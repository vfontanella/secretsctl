package utils

import (
	"fmt"
	"os"
	"os/exec"
)

func DoctorCheck() error {
	check := func(name string, fn func() error) error {
		if err := fn(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Printf("✔ %s\n", name)
		return nil
	}

	if err := check("sops installed", func() error {
		_, err := exec.LookPath("sops")
		return err
	}); err != nil {
		return err
	}

	if err := check("age-keygen installed", func() error {
		_, err := exec.LookPath("age-keygen")
		return err
	}); err != nil {
		return err
	}

	if err := check("AWS credentials present", func() error {
		if os.Getenv("AWS_REGION") == "" {
			return fmt.Errorf("AWS_REGION not set")
		}
		return nil
	}); err != nil {
		return err
	}

	fmt.Println("Environment looks healthy")
	return nil
}
