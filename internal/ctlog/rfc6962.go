package ctlog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

// NewRFC6962Client constructs a signature-verifying CT client using a pinned DER public key.
func NewRFC6962Client(endpoint string, publicKeyDER []byte, httpClient *http.Client) (LogClient, string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, "", fmt.Errorf("CT endpoint must be an absolute HTTPS URL")
	}
	if len(publicKeyDER) == 0 || httpClient == nil || httpClient.Timeout <= 0 {
		return nil, "", fmt.Errorf("pinned CT public key and HTTP client timeout are required")
	}
	logClient, err := client.New(endpoint, httpClient, jsonclient.Options{PublicKeyDER: publicKeyDER, UserAgent: "cloudattrib-ct/1"})
	if err != nil {
		return nil, "", fmt.Errorf("create RFC 6962 client: %w", err)
	}
	digest := sha256.Sum256(publicKeyDER)
	return logClient, "sha256:" + hex.EncodeToString(digest[:]), nil
}

var _ LogClient = (*client.LogClient)(nil)
