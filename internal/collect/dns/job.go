package dns

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

type cachedQuery struct {
	ready      chan struct{}
	result     model.DNSResult
	err        error
	observedAt time.Time
	expiresAt  time.Time
}

// Job owns query reuse for one analysis attempt. It never shares answers across jobs.
type Job struct {
	collector *Collector
	mu        sync.Mutex
	queries   map[model.DNSQuestion]*cachedQuery
	used      int
	limit     int
}

// NewJob creates an independent bounded DNS query cache.
func (c *Collector) NewJob() *Job {
	limit := c.limits.DNSQuestions
	if limit <= 0 {
		limit = policy.DefaultLimits().DNSQuestions
	}
	return &Job{collector: c, queries: make(map[model.DNSQuestion]*cachedQuery), limit: limit}
}

func (j *Job) query(ctx context.Context, question model.DNSQuestion) (model.DNSResult, time.Time, bool, error) {
	if normalized := normalizedGraphName(question.Name); normalized != "" {
		question.Name = normalized
	}
	if err := ctx.Err(); err != nil {
		return model.DNSResult{Question: question, Outcome: outcomeForError(err)}, j.collector.now(), false, err
	}
	var entry *cachedQuery
	for {
		j.mu.Lock()
		entry = j.queries[question]
		if entry != nil {
			select {
			case <-entry.ready:
				if !entry.expiresAt.After(j.collector.now()) {
					delete(j.queries, question)
					j.mu.Unlock()
					continue
				}
				result, err, observedAt := entry.result, entry.err, entry.observedAt
				j.mu.Unlock()
				return result, observedAt, true, err
			default:
			}
			j.mu.Unlock()
			select {
			case <-ctx.Done():
				return model.DNSResult{Question: question, Outcome: outcomeForError(ctx.Err())}, j.collector.now(), true, ctx.Err()
			case <-entry.ready:
				return entry.result, entry.observedAt, true, entry.err
			}
		}
		if j.used >= j.limit {
			j.mu.Unlock()
			err := model.NewError(model.CodeBudgetExceeded, "DNS question budget exhausted", nil)
			return model.DNSResult{Question: question, Outcome: model.DNSOutcomeBudgetExhausted}, j.collector.now(), false, err
		}
		entry = &cachedQuery{ready: make(chan struct{})}
		j.queries[question] = entry
		j.used++
		j.mu.Unlock()
		break
	}

	result, err := j.collector.query(ctx, question)
	if result.Question.Name == "" {
		result.Question = question
	}
	observedAt := j.collector.now()
	var expiresAt time.Time
	if ttl := cacheTTL(result, err); ttl > 0 {
		expiresAt = observedAt.Add(time.Duration(ttl) * time.Second)
	}
	j.mu.Lock()
	entry.result, entry.err, entry.observedAt, entry.expiresAt = result, err, observedAt, expiresAt
	close(entry.ready)
	j.mu.Unlock()
	return result, observedAt, false, err
}

func cacheTTL(result model.DNSResult, err error) uint32 {
	if err != nil {
		return 0
	}
	switch normalizeOutcome(result, nil) {
	case model.DNSOutcomeNoData, model.DNSOutcomeNXDomain:
		return result.NegativeTTL
	case model.DNSOutcomeAnswered:
		if len(result.Records) == 0 {
			return 0
		}
		var ttl uint32
		for _, record := range result.Records {
			var payload model.DNSPayload
			if json.Unmarshal(record.Payload, &payload) != nil || payload.TTL == 0 {
				return 0
			}
			if ttl == 0 || payload.TTL < ttl {
				ttl = payload.TTL
			}
		}
		return ttl
	default:
		return 0
	}
}

// CollectOccurrence collects one seed using this job's shared query budget and cache.
func (j *Job) CollectOccurrence(ctx context.Context, hostname string, port uint16, occurrence model.ObservationOccurrence, onCandidate func(Candidate)) Result {
	return j.collector.collectOccurrence(ctx, j, hostname, port, occurrence, onCandidate)
}

// Query reuses a DNS question within this analysis job while its TTL remains valid.
func (j *Job) Query(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
	result, _, _, err := j.query(ctx, question)
	return result, err
}

// QueryWithObservedAt returns the original collection time on cache hits.
func (j *Job) QueryWithObservedAt(ctx context.Context, question model.DNSQuestion) (model.DNSResult, time.Time, error) {
	result, observedAt, _, err := j.query(ctx, question)
	return result, observedAt, err
}
