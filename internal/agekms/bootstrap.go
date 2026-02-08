package agekms

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
)

func Bootstrap() (string, error) {

	// Existing encrypted key → verify only
	if _, err := os.Stat(EncryptedKey); err == nil {
		key, err := DecryptAGE()
		if err != nil {
			return "", err
		}

		pub, err := extractPublicKey(key)
		if err != nil {
			return "", err
		}

		if err := VerifyFingerprint(pub); err != nil {
			return "", err
		}

		fmt.Println("AGE key verified (encrypted key + fingerprint match)")
		return pub, nil
	}

	// Fingerprint exists but encrypted key does not
	if _, err := os.Stat(FingerprintFile); err == nil {
		return "", fmt.Errorf(
			"fingerprint exists but encrypted AGE key is missing; refusing to regenerate",
		)
	}

	// Fresh bootstrap
	cmd := exec.Command("age-keygen")
	cmd.Stderr = os.Stderr

	key, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("age-keygen failed: %w", err)
	}

	pub, err := extractPublicKey(key)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(pub))
	if err := os.WriteFile(
		FingerprintFile,
		[]byte(fmt.Sprintf("%x", sum)),
		0600,
	); err != nil {
		return "", err
	}

	if err := EncryptAGE(key); err != nil {
		return "", err
	}

	fmt.Println("AGE key generated, fingerprinted, and encrypted")
	return pub, nil
}
