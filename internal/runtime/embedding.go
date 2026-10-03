package runtime

import (
	"context"
	"errors"
	"time"

	"cloudattrib/internal/embedding"
	"cloudattrib/internal/store/postgres"
)

// runInventoryEmbeddings owns one bounded local indexing loop. Inference runs
// outside database transactions and cannot consume the ordinary service pool.
func runInventoryEmbeddings(ctx context.Context, store *postgres.Store, provider *embedding.Provider, onError func(error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		generations, err := store.EmbeddingGenerationsWithPendingWork(ctx, 4)
		if err != nil && !errors.Is(err, context.Canceled) {
			onError(err)
		}
		if err == nil {
			for _, generation := range generations {
				embedder, loadErr := provider.ForGeneration(ctx, generation)
				if loadErr != nil {
					if !errors.Is(loadErr, context.Canceled) {
						onError(loadErr)
					}
					continue
				}
				for i := 0; i < 10; i++ {
					processed, processErr := store.ProcessNextInventoryEmbedding(ctx, generation.ID, embedder)
					if processErr != nil {
						if !errors.Is(processErr, context.Canceled) {
							onError(processErr)
						}
						break
					}
					if !processed {
						break
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
