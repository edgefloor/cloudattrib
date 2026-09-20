package ctlog

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
)

func TestRFC6962ClientRejectsBadCheckpointSignature(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	invalidSignature, err := cttls.Marshal(cttls.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA}, Signature: []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("marshal invalid signature: %v", err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != ct.GetSTHPath {
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(ct.GetSTHResponse{
			TreeSize: 1, Timestamp: uint64(time.Now().UnixMilli()), SHA256RootHash: make([]byte, 32), TreeHeadSignature: invalidSignature,
		})
	}))
	t.Cleanup(server.Close)
	server.Client().Timeout = time.Second
	client, _, err := NewRFC6962Client(server.URL, publicKey, server.Client())
	if err != nil {
		t.Fatalf("NewRFC6962Client() error = %v", err)
	}
	if _, err := client.GetSTH(context.Background()); err == nil {
		t.Fatal("GetSTH() error = nil, want invalid signature")
	}
}
