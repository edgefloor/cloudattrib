package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

// SearchInventory returns one hostname-ordered page of known assets.
func (s *Store) SearchInventory(ctx context.Context, request inventory.SearchRequest, after string) (inventory.Page, error) {
	filter, argument := inventorySearchPredicate(request)
	query := `SELECT a.asset_id,a.hostname,a.normalization_version,a.archived_at,a.deletion_generation
		FROM inventory_assets a WHERE a.hostname > $1 AND ($2 OR a.archived_at IS NULL) AND ` + filter + `
		ORDER BY a.hostname COLLATE "C" LIMIT $4`
	arguments := []any{after, request.IncludeArchived, argument, request.Limit + 1}
	if request.ScopeRoot != "" {
		query = `SELECT a.asset_id,a.hostname,a.normalization_version,a.archived_at,a.deletion_generation
			FROM inventory_memberships m JOIN inventory_assets a ON a.asset_id=m.asset_id
			WHERE m.root=$4 AND m.hostname > $1 AND ($2 OR a.archived_at IS NULL) AND ` + filter + `
			ORDER BY m.hostname COLLATE "C" LIMIT $5`
		arguments = []any{after, request.IncludeArchived, argument, request.ScopeRoot, request.Limit + 1}
	}
	if request.Mode == inventory.SearchDescendant {
		// Materialize the label-boundary candidate set before hostname ordering.
		// Otherwise LIMIT can make PostgreSQL scan hostname order and filter
		// almost the entire inventory for a selective descendant root.
		candidates := `WITH candidates AS MATERIALIZED (
			SELECT asset_id,hostname,normalization_version,archived_at,deletion_generation FROM inventory_assets WHERE reversed_labels LIKE $3 ESCAPE '\'
			AND reversed_labels <> left($3,length($3)-1)
		) `
		if request.ScopeRoot == "" {
			query = candidates + `SELECT a.asset_id,a.hostname,a.normalization_version,a.archived_at,a.deletion_generation
				FROM candidates a
				WHERE a.hostname > $1 AND ($2 OR a.archived_at IS NULL)
				ORDER BY a.hostname COLLATE "C" LIMIT $4`
		} else {
			query = candidates + `SELECT a.asset_id,a.hostname,a.normalization_version,a.archived_at,a.deletion_generation
				FROM candidates a JOIN inventory_memberships m ON m.asset_id=a.asset_id AND m.root=$4
				WHERE a.hostname > $1 AND ($2 OR a.archived_at IS NULL)
				ORDER BY a.hostname COLLATE "C" LIMIT $5`
		}
	}
	rows, err := s.pool.Query(ctx, query, arguments...)
	if err != nil {
		return inventory.Page{}, persistence("search inventory", err)
	}
	page := inventory.Page{Items: make([]inventory.Asset, 0, request.Limit)}
	for rows.Next() {
		var asset inventory.Asset
		if err := rows.Scan(&asset.ID, &asset.Hostname, &asset.NormalizationVersion, &asset.ArchivedAt, &asset.DeletionGeneration); err != nil {
			rows.Close()
			return inventory.Page{}, persistence("scan inventory asset", err)
		}
		page.Items = append(page.Items, asset)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inventory.Page{}, persistence("iterate inventory assets", err)
	}
	rows.Close()
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		page.NextCursor = inventory.NextCursor(request, page.Items[len(page.Items)-1].Hostname)
	}
	if err := s.populateInventoryFacts(ctx, page.Items); err != nil {
		return inventory.Page{}, err
	}
	return page, nil
}

func inventorySearchPredicate(request inventory.SearchRequest) (string, string) {
	switch request.Mode {
	case inventory.SearchExact:
		return `a.hostname = $3`, request.Query
	case inventory.SearchDescendant:
		return `a.reversed_labels LIKE $3 ESCAPE '\' AND a.reversed_labels <> left($3,length($3)-1)`, inventory.ReverseLabels(request.Query) + "%"
	case inventory.SearchPrefix:
		return `a.hostname LIKE $3 ESCAPE '\'`, escapeInventoryLike(request.Query) + "%"
	case inventory.SearchPartial:
		return `a.hostname LIKE $3 ESCAPE '\'`, "%" + escapeInventoryLike(request.Query) + "%"
	default:
		return `a.hostname >= $3`, ""
	}
}

func escapeInventoryLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// ReadInventory returns one hostname and its source and scope facts.
func (s *Store) ReadInventory(ctx context.Context, hostname string) (inventory.Asset, error) {
	var asset inventory.Asset
	err := s.pool.QueryRow(ctx, `SELECT asset_id,hostname,normalization_version,archived_at,deletion_generation FROM inventory_assets WHERE hostname=$1`, hostname).
		Scan(&asset.ID, &asset.Hostname, &asset.NormalizationVersion, &asset.ArchivedAt, &asset.DeletionGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.Asset{}, model.NewError(model.CodeNotFound, "inventory asset not found", nil)
	}
	if err != nil {
		return inventory.Asset{}, persistence("read inventory asset", err)
	}
	items := []inventory.Asset{asset}
	if err := s.populateInventoryFacts(ctx, items); err != nil {
		return inventory.Asset{}, err
	}
	return items[0], nil
}

// ReadInventoryByID resolves an explicit stable asset selection.
func (s *Store) ReadInventoryByID(ctx context.Context, id string) (inventory.Asset, error) {
	var asset inventory.Asset
	err := s.pool.QueryRow(ctx, `SELECT asset_id,hostname,normalization_version,archived_at,deletion_generation FROM inventory_assets WHERE asset_id=$1`, id).
		Scan(&asset.ID, &asset.Hostname, &asset.NormalizationVersion, &asset.ArchivedAt, &asset.DeletionGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.Asset{}, model.NewError(model.CodeNotFound, "inventory asset not found", nil)
	}
	if err != nil {
		return inventory.Asset{}, persistence("read inventory asset by ID", err)
	}
	items := []inventory.Asset{asset}
	if err := s.populateInventoryFacts(ctx, items); err != nil {
		return inventory.Asset{}, err
	}
	return items[0], nil
}

// ArchiveInventory changes default visibility while preserving all source facts.
func (s *Store) ArchiveInventory(ctx context.Context, hostname string, archived bool) (inventory.Asset, error) {
	var err error
	if archived {
		_, err = s.pool.Exec(ctx, `UPDATE inventory_assets SET archived_at=COALESCE(archived_at,clock_timestamp()) WHERE hostname=$1`, hostname)
	} else {
		_, err = s.pool.Exec(ctx, `UPDATE inventory_assets SET archived_at=NULL WHERE hostname=$1`, hostname)
	}
	if err != nil {
		return inventory.Asset{}, persistence("archive inventory asset", err)
	}
	return s.ReadInventory(ctx, hostname)
}

// DeleteInventory removes inventory-owned facts and optionally suppresses rediscovery.
func (s *Store) DeleteInventory(ctx context.Context, hostname string, suppress bool) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, persistence("begin inventory deletion", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockInventoryHostname(ctx, tx, hostname); err != nil {
		return 0, err
	}
	var generation int64
	if err := tx.QueryRow(ctx, `INSERT INTO inventory_tombstones(hostname,deletion_generation,suppressed)
		VALUES($1,1,$2) ON CONFLICT (hostname) DO UPDATE SET
		deletion_generation=inventory_tombstones.deletion_generation+1,suppressed=EXCLUDED.suppressed,deleted_at=clock_timestamp()
		RETURNING deletion_generation`, hostname, suppress).Scan(&generation); err != nil {
		return 0, persistence("record inventory deletion", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM inventory_assets WHERE hostname=$1`, hostname); err != nil {
		return 0, persistence("delete inventory asset", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, persistence("commit inventory deletion", err)
	}
	return generation, nil
}

func (s *Store) populateInventoryFacts(ctx context.Context, assets []inventory.Asset) error {
	if len(assets) == 0 {
		return nil
	}
	ids := make([]string, len(assets))
	byID := make(map[string]int, len(assets))
	for index := range assets {
		ids[index] = assets[index].ID
		byID[assets[index].ID] = index
		assets[index].Scopes = []string{}
		assets[index].Sources = []inventory.Source{}
	}
	rows, err := s.pool.Query(ctx, `SELECT asset_id,root FROM inventory_memberships WHERE asset_id=ANY($1) ORDER BY asset_id,root`, ids)
	if err != nil {
		return persistence("read inventory memberships", err)
	}
	for rows.Next() {
		var id, root string
		if err := rows.Scan(&id, &root); err != nil {
			rows.Close()
			return persistence("scan inventory membership", err)
		}
		assets[byID[id]].Scopes = append(assets[byID[id]].Scopes, root)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return persistence("iterate inventory memberships", err)
	}
	rows.Close()
	rows, err = s.pool.Query(ctx, `SELECT asset_id,source_kind,source_id,provenance,verification,first_observed_at,last_observed_at,
		first_received_at,last_received_at,provenance_ref,log_id,entry_index,checkpoint_id FROM inventory_sources WHERE asset_id=ANY($1)
		ORDER BY asset_id,source_kind,source_id,provenance`, ids)
	if err != nil {
		return persistence("read inventory sources", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var source inventory.Source
		if err := rows.Scan(&id, &source.Kind, &source.ID, &source.Provenance, &source.Verification,
			&source.FirstObservedAt, &source.LastObservedAt, &source.FirstReceivedAt, &source.LastReceivedAt, &source.Reference,
			&source.LogID, &source.EntryIndex, &source.CheckpointID); err != nil {
			return persistence("scan inventory source", err)
		}
		assets[byID[id]].Sources = append(assets[byID[id]].Sources, source)
	}
	if err := rows.Err(); err != nil {
		return persistence("iterate inventory sources", err)
	}
	return nil
}
