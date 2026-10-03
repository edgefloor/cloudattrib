package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

// SearchInventoryEvidence ranks retained descriptions in one context and scope.
func (s *Store) SearchInventoryEvidence(ctx context.Context, request inventory.EvidenceQuery) (inventory.EvidencePage, error) {
	query := `SELECT a.asset_id,a.hostname,c.context_id,c.description,c.description_revision,c.description_hash,
		COALESCE(c.description_report_id,''),c.description_evidence_ids,c.description_observation_ids,c.coverage,c.latest_coverage,c.omitted,
		c.latest_attempt_at,COALESCE(c.latest_attempt_report_id,''),c.last_positive_at,COALESCE(c.last_positive_report_id,''),
		c.latest_http_status,c.latest_http_at,c.last_http_response_status,c.last_http_response_at,COALESCE(c.last_http_response_report_id,''),
		ts_rank_cd(c.search_vector,plainto_tsquery('simple',$2)) AS rank
		FROM inventory_asset_contexts c JOIN inventory_assets a ON a.asset_id=c.asset_id
		WHERE c.context_id=$1 AND a.archived_at IS NULL AND c.search_vector @@ plainto_tsquery('simple',$2)
		ORDER BY rank DESC,a.hostname COLLATE "C" LIMIT $3`
	arguments := []any{request.ContextID, request.Text, request.Limit + 1}
	if request.ScopeRoot != "" {
		query = `SELECT a.asset_id,a.hostname,c.context_id,c.description,c.description_revision,c.description_hash,
			COALESCE(c.description_report_id,''),c.description_evidence_ids,c.description_observation_ids,c.coverage,c.latest_coverage,c.omitted,
			c.latest_attempt_at,COALESCE(c.latest_attempt_report_id,''),c.last_positive_at,COALESCE(c.last_positive_report_id,''),
			c.latest_http_status,c.latest_http_at,c.last_http_response_status,c.last_http_response_at,COALESCE(c.last_http_response_report_id,''),
			ts_rank_cd(c.search_vector,plainto_tsquery('simple',$2)) AS rank
			FROM inventory_memberships m JOIN inventory_asset_contexts c ON c.asset_id=m.asset_id
			JOIN inventory_assets a ON a.asset_id=c.asset_id
			WHERE c.context_id=$1 AND m.root=$3 AND a.archived_at IS NULL AND c.search_vector @@ plainto_tsquery('simple',$2)
			ORDER BY rank DESC,a.hostname COLLATE "C" LIMIT $4`
		arguments = []any{request.ContextID, request.Text, request.ScopeRoot, request.Limit + 1}
	}
	rows, err := s.pool.Query(ctx, query, arguments...)
	if err != nil {
		return inventory.EvidencePage{}, persistence("search inventory descriptions", err)
	}
	defer rows.Close()
	page := inventory.EvidencePage{Items: make([]inventory.EvidenceResult, 0, request.Limit)}
	for rows.Next() {
		item, err := scanInventoryEvidence(rows)
		if err != nil {
			return inventory.EvidencePage{}, persistence("scan inventory description", err)
		}
		item.MatchedTerms = matchedInventoryTerms(item.Description, request.Text)
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return inventory.EvidencePage{}, persistence("iterate inventory descriptions", err)
	}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		page.Truncated = true
	}
	return page, nil
}

func scanInventoryEvidence(row pgx.Row) (inventory.EvidenceResult, error) {
	var item inventory.EvidenceResult
	var rank float32
	err := row.Scan(&item.AssetID, &item.Hostname, &item.ContextID, &item.Description, &item.DescriptionRevision,
		&item.DescriptionHash, &item.DescriptionReportID, &item.EvidenceIDs, &item.ObservationIDs, &item.Coverage, &item.LatestCoverage, &item.Omitted,
		&item.LatestAttemptAt, &item.LatestAttemptReportID, &item.LastPositiveAt, &item.LastPositiveReportID,
		&item.LatestHTTPStatus, &item.LatestHTTPAt, &item.LastHTTPResponseStatus, &item.LastHTTPResponseAt, &item.LastHTTPResponseReportID, &rank)
	item.Rank = float64(rank)
	item.ProjectionStatus = "ready"
	return item, err
}

// ReadInventoryEvidence returns one context projection or its pending state.
func (s *Store) ReadInventoryEvidence(ctx context.Context, hostname, contextID string) (inventory.EvidenceResult, error) {
	query := `SELECT a.asset_id,a.hostname,c.context_id,c.description,c.description_revision,c.description_hash,
		COALESCE(c.description_report_id,''),c.description_evidence_ids,c.description_observation_ids,c.coverage,c.latest_coverage,c.omitted,
		c.latest_attempt_at,COALESCE(c.latest_attempt_report_id,''),c.last_positive_at,COALESCE(c.last_positive_report_id,''),
		c.latest_http_status,c.latest_http_at,c.last_http_response_status,c.last_http_response_at,COALESCE(c.last_http_response_report_id,''),0::real
		FROM inventory_assets a JOIN inventory_asset_contexts c ON c.asset_id=a.asset_id
		WHERE a.hostname=$1 AND c.context_id=$2`
	item, err := scanInventoryEvidence(s.pool.QueryRow(ctx, query, hostname, contextID))
	if err == nil {
		item.MatchedTerms = []string{}
		questions, err := s.inventoryDNSQuestions(ctx, item.AssetID, contextID)
		if err != nil {
			return inventory.EvidenceResult{}, err
		}
		item.DNSQuestions = questions
		return item, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return inventory.EvidenceResult{}, persistence("read inventory description", err)
	}
	var assetID string
	if err := s.pool.QueryRow(ctx, `SELECT asset_id FROM inventory_assets WHERE hostname=$1`, hostname).Scan(&assetID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return inventory.EvidenceResult{}, model.NewError(model.CodeNotFound, "inventory asset not found", nil)
		}
		return inventory.EvidenceResult{}, persistence("read inventory evidence asset", err)
	}
	return inventory.EvidenceResult{AssetID: assetID, Hostname: hostname, ContextID: contextID, EvidenceIDs: []string{}, ObservationIDs: []string{}, Coverage: []string{}, LatestCoverage: []string{}, MatchedTerms: []string{}, ProjectionStatus: "pending"}, nil
}

func (s *Store) inventoryDNSQuestions(ctx context.Context, assetID, contextID string) ([]inventory.DNSQuestionState, error) {
	rows, err := s.pool.Query(ctx, `SELECT question_name,rrtype,latest_observed_at,latest_outcome,latest_report_id,
		last_positive_at,COALESCE(last_positive_report_id,'') FROM inventory_dns_state
		WHERE asset_id=$1 AND context_id=$2 ORDER BY question_name,rrtype`, assetID, contextID)
	if err != nil {
		return nil, persistence("read inventory DNS questions", err)
	}
	defer rows.Close()
	questions := []inventory.DNSQuestionState{}
	for rows.Next() {
		var question inventory.DNSQuestionState
		if err := rows.Scan(&question.QuestionName, &question.RRType, &question.LatestObservedAt,
			&question.LatestOutcome, &question.LatestReportID, &question.LastPositiveAt, &question.LastPositiveReportID); err != nil {
			return nil, persistence("scan inventory DNS question", err)
		}
		questions = append(questions, question)
	}
	if err := rows.Err(); err != nil {
		return nil, persistence("iterate inventory DNS questions", err)
	}
	return questions, nil
}

func matchedInventoryTerms(description, query string) []string {
	lower := strings.ToLower(description)
	seen := map[string]bool{}
	terms := make([]string, 0)
	for _, term := range strings.Fields(strings.ToLower(query)) {
		if !seen[term] && strings.Contains(lower, term) {
			terms = append(terms, term)
			seen[term] = true
		}
	}
	return terms
}
