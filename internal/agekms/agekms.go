package agekms

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	EncryptedKey    = "age-key.encrypted"
	FingerprintFile = ".age-key.fingerprint"
)

func kmsClient() (*kms.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(cfg), nil
}

func kmsKeyID() (*string, error) {
	id := os.Getenv("SECRETSCTL_KMS_KEY_ID")
	if id == "" {
		return nil, fmt.Errorf("SECRETSCTL_KMS_KEY_ID is not set")
	}
	return aws.String(id), nil
}

func EncryptAGE(plain []byte) error {
	k, err := kmsClient()
	if err != nil {
		return err
	}

	keyID, err := kmsKeyID()
	if err != nil {
		return err
	}

	out, err := k.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:     keyID,
		Plaintext: plain,
		EncryptionContext: map[string]string{
			"purpose": "age-key",
		},
	})
	if err != nil {
		return err
	}

	return os.WriteFile(EncryptedKey, out.CiphertextBlob, 0600)
}

func DecryptAGE() ([]byte, error) {
	data, err := os.ReadFile(EncryptedKey)
	if err != nil {
		return nil, err
	}

	k, err := kmsClient()
	if err != nil {
		return nil, err
	}

	out, err := k.Decrypt(context.Background(), &kms.DecryptInput{
		CiphertextBlob: data,
		EncryptionContext: map[string]string{
			"purpose": "age-key",
		},
	})
	if err != nil {
		return nil, err
	}

	return out.Plaintext, nil
}

func VerifyFingerprint(pubkey string) error {
	sum := sha256.Sum256([]byte(pubkey))
	expected, err := os.ReadFile(FingerprintFile)
	if err != nil {
		return err
	}

	if strings.TrimSpace(fmt.Sprintf("%x", sum)) != strings.TrimSpace(string(expected)) {
		return fmt.Errorf("AGE fingerprint mismatch")
	}
	return nil
}

