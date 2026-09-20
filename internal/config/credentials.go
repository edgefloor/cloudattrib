package config

import (
	"fmt"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

const maximumCredentialsBytes = 64 << 10

// LoadCredentials reads a private YAML or JSON mapping of bearer tokens to operator IDs.
func LoadCredentials(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open API credentials: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumCredentialsBytes {
		return nil, fmt.Errorf("API credentials must be a private non-empty regular file no larger than 64 KiB")
	}
	credentials := map[string]string{}
	decoder := yaml.NewDecoder(io.LimitReader(file, maximumCredentialsBytes+1))
	if err := decoder.Decode(&credentials); err != nil {
		return nil, fmt.Errorf("decode API credentials: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("API credentials contain trailing data")
	}
	if len(credentials) == 0 {
		return nil, fmt.Errorf("API credentials are empty")
	}
	for credential, operatorID := range credentials {
		if credential == "" || strings.TrimSpace(operatorID) == "" {
			return nil, fmt.Errorf("API credentials and operator IDs must be non-empty")
		}
		credentials[credential] = strings.TrimSpace(operatorID)
	}
	return credentials, nil
}
