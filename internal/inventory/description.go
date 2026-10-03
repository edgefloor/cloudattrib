package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"cloudattrib/internal/model"
)

// DescriptionFormatVersion identifies the deterministic retained-fact rendering contract.
const DescriptionFormatVersion = "3"
const maximumDescriptionBytes = 1024
const maximumDescriptionWords = 128
const maximumDescriptionRefs = 100

// Description contains deterministic, bounded terms and links to retained evidence.
// It never copies raw TXT, headers, cookies, query strings, scripts, or bodies.
type Description struct {
	FormatVersion  string    `json:"format_version"`
	Text           string    `json:"text"`
	ContentHash    string    `json:"content_hash"`
	ReportID       string    `json:"report_id"`
	ObservedAt     time.Time `json:"observed_at"`
	AttemptedAt    time.Time `json:"attempted_at"`
	Positive       bool      `json:"positive"`
	ObservationIDs []string  `json:"observation_ids"`
	EvidenceIDs    []string  `json:"evidence_ids"`
	Coverage       []string  `json:"coverage"`
	Omitted        int       `json:"omitted"`
}

// DescribeReport builds searchable terms from retained typed facts for one asset.
func DescribeReport(report model.Report, hostname string) Description {
	description := Description{FormatVersion: DescriptionFormatVersion, ReportID: report.ID, AttemptedAt: report.EndedAt,
		ObservationIDs: []string{}, EvidenceIDs: []string{}, Coverage: []string{}}
	terms := []string{"hostname " + hostname}
	priority := map[string]int{"hostname " + hostname: 0}
	addTerm := func(term string, rank int) {
		terms = append(terms, term)
		if current, ok := priority[term]; !ok || rank < current {
			priority[term] = rank
		}
	}
	for _, observation := range report.Observations {
		if observation.Subject != hostname || observation.Scope == model.ScopeExternalRedirect || observation.Scope == model.ScopeMailDependency || observation.Scope == model.ScopeDNSDependency {
			continue
		}
		if observation.ObservedAt.After(description.ObservedAt) {
			description.ObservedAt = observation.ObservedAt
		}
		switch observation.Type {
		case "dns_query":
			var payload model.DNSPayload
			if json.Unmarshal(observation.Payload, &payload) != nil {
				description.Omitted++
				continue
			}
			rrtype := safeDescriptionToken(payload.RRType)
			outcome := safeDescriptionToken(observation.Status)
			if rrtype == "" || outcome == "" {
				description.Omitted++
				continue
			}
			addTerm("DNS "+rrtype+" "+outcome, 2)
			if observation.Status == string(model.DNSOutcomeAnswered) {
				description.Positive = true
			}
		case "dns_record", "dns_address":
			var payload model.DNSPayload
			if json.Unmarshal(observation.Payload, &payload) != nil {
				description.Omitted++
				continue
			}
			rrtype := safeDescriptionToken(payload.RRType)
			if rrtype == "" {
				description.Omitted++
				continue
			}
			addTerm("DNS "+rrtype+" record", 2)
			description.Positive = true
		case "http_response":
			var payload model.HTTPPayload
			if json.Unmarshal(observation.Payload, &payload) != nil {
				description.Omitted++
				continue
			}
			if payload.StatusCode >= 100 && payload.StatusCode <= 599 {
				addTerm(fmt.Sprintf("HTTP %d response", payload.StatusCode), 2)
				description.Positive = true
			}
		case "technology":
			var payload model.TechnologyPayload
			if json.Unmarshal(observation.Payload, &payload) != nil {
				description.Omitted++
				continue
			}
			if name := safeDescriptionLabel(payload.Name); name != "" {
				addTerm("technology "+name, 1)
			}
		}
		if observation.ID != "" {
			description.ObservationIDs = append(description.ObservationIDs, observation.ID)
		}
	}
	for _, finding := range report.Findings {
		if finding.Subject != hostname || finding.Scope == model.ScopeExternalRedirect || finding.Scope == model.ScopeMailDependency || finding.Scope == model.ScopeDNSDependency {
			continue
		}
		for _, value := range []string{finding.ProviderID, finding.ProductID, finding.Category, string(finding.Relation)} {
			if token := safeDescriptionToken(value); token != "" {
				addTerm(token, 1)
			}
		}
		description.EvidenceIDs = append(description.EvidenceIDs, finding.EvidenceIDs...)
	}
	for _, coverage := range report.Coverage {
		capability, status := safeDescriptionToken(coverage.Capability), safeDescriptionToken(string(coverage.Status))
		if capability != "" && status != "" {
			description.Coverage = append(description.Coverage, capability+":"+status)
		}
	}
	slices.Sort(terms)
	terms = slices.Compact(terms)
	slices.Sort(description.ObservationIDs)
	description.ObservationIDs = slices.Compact(description.ObservationIDs)
	slices.Sort(description.EvidenceIDs)
	description.EvidenceIDs = slices.Compact(description.EvidenceIDs)
	slices.Sort(description.Coverage)
	description.Coverage = slices.Compact(description.Coverage)
	if len(description.ObservationIDs) > maximumDescriptionRefs {
		description.Omitted += len(description.ObservationIDs) - maximumDescriptionRefs
		description.ObservationIDs = description.ObservationIDs[:maximumDescriptionRefs]
	}
	if len(description.EvidenceIDs) > maximumDescriptionRefs {
		description.Omitted += len(description.EvidenceIDs) - maximumDescriptionRefs
		description.EvidenceIDs = description.EvidenceIDs[:maximumDescriptionRefs]
	}
	for len(terms) > 1 && (len(strings.Join(terms, " ")) > maximumDescriptionBytes || len(strings.Fields(strings.Join(terms, " "))) > maximumDescriptionWords) {
		description.Omitted++
		remove := -1
		for index := range terms {
			if priority[terms[index]] == 0 {
				continue
			}
			if remove < 0 || priority[terms[index]] > priority[terms[remove]] || priority[terms[index]] == priority[terms[remove]] && terms[index] > terms[remove] {
				remove = index
			}
		}
		if remove < 0 {
			break
		}
		terms = append(terms[:remove], terms[remove+1:]...)
	}
	description.Text = strings.Join(terms, " ")
	digest := sha256.Sum256([]byte(description.FormatVersion + "\x00" + description.Text))
	description.ContentHash = "sha256:" + hex.EncodeToString(digest[:])
	return description
}

func safeDescriptionToken(value string) string {
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, character := range value {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) && character != '.' && character != '-' && character != '_' {
			return ""
		}
	}
	return strings.ToLower(value)
}

// safeDescriptionLabel accepts the word separators used by passive technology
// names while rejecting URL, control, and header punctuation from search text.
func safeDescriptionLabel(value string) string {
	if value == "" || len(value) > 128 {
		return ""
	}
	words := strings.Fields(value)
	if len(words) == 0 || len(words) > 8 || strings.Join(words, " ") != value {
		return ""
	}
	for _, word := range words {
		if safeDescriptionToken(word) == "" {
			return ""
		}
	}
	return strings.ToLower(value)
}
