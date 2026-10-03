package postgres

import (
	"context"
	"strings"
	"unicode"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

// SearchInventoryRetrievalLexical ranks assets matching any bounded query term.
// The evidence search endpoint keeps its stricter all-terms behavior.
func (s *Store) SearchInventoryRetrievalLexical(ctx context.Context, request inventory.EvidenceQuery) (inventory.EvidencePage, error) {
	if request.ContextID == "" || request.Limit < 1 || request.Limit > 100 {
		return inventory.EvidencePage{}, model.NewError(model.CodeInvalidOptions, "invalid retrieval context or limit", nil)
	}
	tsquery, err := retrievalTSQuery(request.Text)
	if err != nil {
		return inventory.EvidencePage{}, err
	}
	query := `SELECT a.asset_id,a.hostname,c.context_id,c.description,c.description_revision,c.description_hash,
		COALESCE(c.description_report_id,''),c.description_evidence_ids,c.description_observation_ids,c.coverage,c.latest_coverage,c.omitted,
		c.latest_attempt_at,COALESCE(c.latest_attempt_report_id,''),c.last_positive_at,COALESCE(c.last_positive_report_id,''),
		c.latest_http_status,c.latest_http_at,c.last_http_response_status,c.last_http_response_at,COALESCE(c.last_http_response_report_id,''),
		ts_rank_cd(c.search_vector,to_tsquery('simple',$2)) AS rank
		FROM inventory_asset_contexts c JOIN inventory_assets a ON a.asset_id=c.asset_id
		WHERE c.context_id=$1 AND a.archived_at IS NULL AND c.search_vector @@ to_tsquery('simple',$2)
		ORDER BY rank DESC,a.hostname COLLATE "C" LIMIT $3`
	arguments := []any{request.ContextID, tsquery, request.Limit + 1}
	if request.ScopeRoot != "" {
		query = `SELECT a.asset_id,a.hostname,c.context_id,c.description,c.description_revision,c.description_hash,
			COALESCE(c.description_report_id,''),c.description_evidence_ids,c.description_observation_ids,c.coverage,c.latest_coverage,c.omitted,
			c.latest_attempt_at,COALESCE(c.latest_attempt_report_id,''),c.last_positive_at,COALESCE(c.last_positive_report_id,''),
			c.latest_http_status,c.latest_http_at,c.last_http_response_status,c.last_http_response_at,COALESCE(c.last_http_response_report_id,''),
			ts_rank_cd(c.search_vector,to_tsquery('simple',$2)) AS rank
			FROM inventory_memberships m JOIN inventory_asset_contexts c ON c.asset_id=m.asset_id
			JOIN inventory_assets a ON a.asset_id=c.asset_id
			WHERE c.context_id=$1 AND m.root=$3 AND a.archived_at IS NULL AND c.search_vector @@ to_tsquery('simple',$2)
			ORDER BY rank DESC,a.hostname COLLATE "C" LIMIT $4`
		arguments = []any{request.ContextID, tsquery, request.ScopeRoot, request.Limit + 1}
	}
	rows, err := s.pool.Query(ctx, query, arguments...)
	if err != nil {
		return inventory.EvidencePage{}, persistence("search retrieval terms", err)
	}
	defer rows.Close()
	page := inventory.EvidencePage{Items: make([]inventory.EvidenceResult, 0, request.Limit)}
	for rows.Next() {
		item, err := scanInventoryEvidence(rows)
		if err != nil {
			return inventory.EvidencePage{}, persistence("scan retrieval terms", err)
		}
		item.MatchedTerms = matchedInventoryTerms(item.Description, request.Text)
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return inventory.EvidencePage{}, persistence("iterate retrieval terms", err)
	}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		page.Truncated = true
	}
	return page, nil
}

func retrievalTSQuery(text string) (string, error) {
	parts := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	seen := make(map[string]bool, min(len(parts), 32))
	terms := make([]string, 0, min(len(parts), 32))
	for _, part := range parts {
		if part == "" || seen[part] {
			continue
		}
		terms = append(terms, part)
		seen[part] = true
		if len(terms) > 32 {
			return "", model.NewError(model.CodeInvalidOptions, "retrieval text has more than 32 distinct terms", nil)
		}
	}
	if len(terms) == 0 {
		return "", model.NewError(model.CodeInvalidOptions, "retrieval text has no searchable terms", nil)
	}
	return strings.Join(terms, " | "), nil
}
