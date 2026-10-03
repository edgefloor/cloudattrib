// Command generate-inventory-corpus renders synthetic typed report facts through
// the production inventory description path for retrieval evaluation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

type fact struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	DNS        string `json:"dns,omitempty"`
	DNSStatus  string `json:"dns_status,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Technology string `json:"technology,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Product    string `json:"product,omitempty"`
	Category   string `json:"category,omitempty"`
}

type query struct {
	Text     string   `json:"text"`
	Relevant []string `json:"relevant"`
}

type factsFile struct {
	Version string  `json:"version"`
	Facts   []fact  `json:"facts"`
	Queries []query `json:"queries"`
}

type document struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Description string `json:"description"`
}

type corpus struct {
	Version    string     `json:"version"`
	Provenance string     `json:"provenance"`
	Documents  []document `json:"documents"`
	Queries    []query    `json:"queries"`
}

func main() {
	input := flag.String("input", "docs/benchmarks/inventory-retrieval-facts-v2.json", "synthetic typed facts")
	output := flag.String("output", "docs/benchmarks/inventory-retrieval-corpus-v2.json", "rendered corpus")
	flag.Parse()
	if err := generate(*input, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(input, output string) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var source factsFile
	if err := json.Unmarshal(data, &source); err != nil {
		return err
	}
	if source.Version != "2" {
		return fmt.Errorf("unsupported facts version %q", source.Version)
	}
	result := corpus{Version: source.Version, Provenance: "Synthetic typed report facts rendered by inventory.DescribeReport; no live hosts or customer data.", Documents: make([]document, 0, len(source.Facts)), Queries: source.Queries}
	seen := make(map[string]bool, len(source.Facts))
	for _, item := range source.Facts {
		if item.ID == "" || item.Hostname == "" || seen[item.ID] {
			return fmt.Errorf("invalid or duplicate fact %q", item.ID)
		}
		seen[item.ID] = true
		description, err := render(item)
		if err != nil {
			return fmt.Errorf("render %s: %w", item.ID, err)
		}
		result.Documents = append(result.Documents, document{ID: item.ID, Hostname: item.Hostname, Description: description})
	}
	for _, item := range source.Queries {
		if item.Text == "" || len(item.Relevant) == 0 {
			return fmt.Errorf("empty query or relevance judgment")
		}
		for _, id := range item.Relevant {
			if !seen[id] {
				return fmt.Errorf("query %q references unknown document %q", item.Text, id)
			}
		}
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(output, append(encoded, '\n'), 0o644)
}

func render(item fact) (string, error) {
	observed := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	report := model.Report{ID: item.ID, EndedAt: observed}
	addObservation := func(kind, status string, payload any) error {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		report.Observations = append(report.Observations, model.Observation{ID: fmt.Sprintf("%s-%d", item.ID, len(report.Observations)), Type: kind, Subject: item.Hostname, ObservedAt: observed, Status: status, Payload: encoded})
		return nil
	}
	if item.DNS != "" {
		status := item.DNSStatus
		if status == "" {
			status = "answered"
		}
		if err := addObservation("dns_query", status, model.DNSPayload{RRType: item.DNS, Owner: item.Hostname}); err != nil {
			return "", err
		}
	}
	if item.HTTPStatus != 0 {
		if err := addObservation("http_response", "responded", model.HTTPPayload{StatusCode: item.HTTPStatus}); err != nil {
			return "", err
		}
	}
	if item.Technology != "" {
		if err := addObservation("technology", "detected", model.TechnologyPayload{Name: item.Technology}); err != nil {
			return "", err
		}
	}
	if item.Provider != "" || item.Product != "" || item.Category != "" {
		report.Findings = []model.Finding{{Subject: item.Hostname, ProviderID: item.Provider, ProductID: item.Product, Category: item.Category}}
	}
	return inventory.DescribeReport(report, item.Hostname).Text, nil
}
