## secretsctl

A local-first, human-operated secret manager using AGE + SOPS + AWS KMS.

### Requirements

KMS Key to encrypt the age key.

```
export SECRETSCTL_KMS_KEY_ID=alias/my-age-kms-key
```

### Build the cli

```
go mod tidy
go build -o secretsctl ./cmd/secretsctl
```

### Setup

Once the cli command is created, it can be copied to the repository where it will be used to encrypt / decrypt secrets.

### Naming contract

The encryption will not works if the file has the .enc.yaml extension because that is the extension used by the encrypted files to precent double encryption.

- `<secret>.yaml` → plaintext
- `<secret>.enc.yaml` → encrypted

### Bootstrap

Creates the AGE key and encrypt using the KMS key.

```
secretsctl bootstrap
```

The result should be the creation of the files:
.age-key.fingerprint
age-key.encrypted
secretsctl

### Encrypt

secretsctl enc secrets.yaml

### Decrypt

secretsctl dec secrets.enc.yaml

### Validate

secretsctl validate secrets.enc.yaml

### Diff

secretsctl diff secrets.enc.yaml
