package config

import "testing"

func TestEmbeddingConfigRequiresAbsoluteSocketDirectory(t *testing.T) {
	t.Parallel()
	configuration := Default()
	configuration.Embedding.Enabled = true
	configuration.Embedding.SocketDirectory = "relative/sockets"
	if err := configuration.Validate(); err == nil {
		t.Fatal("enabled embeddings accepted a relative socket directory")
	}
	configuration.Embedding.SocketDirectory = "/run/cloudattrib/embedding"
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
}
