package agekms

import (
	"fmt"
	"strings"
)

func extractPublicKey(privateKey []byte) (string, error) {
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
