package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

func runInventory(ctx context.Context, args []string, dependencies Dependencies, streams commandStreams) int {
	if len(args) == 0 {
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "inventory requires an operation", nil))
	}
	switch args[0] {
	case "validate":
		flags := flag.NewFlagSet("inventory validate", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		assetIDs := flags.String("asset-ids", "", "")
		selectionMode := flags.String("selection-mode", "", "")
		query := flags.String("query", "", "")
		scope := flags.String("scope", "", "")
		mode := flags.String("mode", "dns", "")
		bundle := flags.String("bundle", "", "")
		idempotency := flags.String("idempotency-key", "", "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *idempotency == "" || (*assetIDs == "") == (*selectionMode == "") {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "inventory validate requires --idempotency-key and either --asset-ids or --selection-mode", err))
		}
		if dependencies.InventoryValidate == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory validation is unavailable", nil))
		}
		request := inventory.ValidationRequest{IdempotencyKey: *idempotency, BundleID: *bundle, Mode: model.Mode(*mode), ScopeRoot: *scope}
		if *assetIDs != "" {
			request.AssetIDs = strings.Split(*assetIDs, ",")
		} else {
			request.Selection = &inventory.SearchRequest{Mode: inventory.SearchMode(*selectionMode), Query: *query, ScopeRoot: *scope}
		}
		job, err := dependencies.InventoryValidate(ctx, request)
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, job)
	case "import":
		flags := flag.NewFlagSet("inventory import", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		input := flags.String("input", "", "")
		scope := flags.String("scope", "", "")
		source := flags.String("source", "", "")
		operation := flags.String("operation", "", "")
		chunk := flags.String("chunk", "", "")
		format := flags.String("format", "text", "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *input == "" || *scope == "" || *source == "" || *operation == "" || *chunk == "" || (*format != "text" && *format != "jsonl") {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "inventory import requires --input, --scope, --source, --operation, --chunk, and text or jsonl format", err))
		}
		if dependencies.InventoryImport == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory import is unavailable", nil))
		}
		reader := streams.stdin
		if *input != "-" {
			file, err := os.Open(*input)
			if err != nil {
				return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "open inventory input", err))
			}
			defer func() { _ = file.Close() }()
			reader = file
		}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		entries := make([]inventory.Entry, 0)
		for scanner.Scan() {
			if len(entries) >= inventory.MaximumImportEntries {
				return diagnostic(streams.stderr, model.NewError(model.CodeInputTooLarge, "inventory chunk exceeds 1000 entries", nil))
			}
			line := scanner.Text()
			if *format == "text" {
				entries = append(entries, inventory.Entry{Hostname: strings.TrimSpace(line)})
			} else {
				var entry inventory.Entry
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "invalid inventory JSONL entry", err))
				}
				entries = append(entries, entry)
			}
		}
		if err := scanner.Err(); err != nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeInputTooLarge, "read inventory input", err))
		}
		receipt, err := dependencies.InventoryImport(ctx, inventory.ImportRequest{OperationID: *operation, ChunkID: *chunk, SourceID: *source, ScopeRoots: strings.Split(*scope, ","), Entries: entries})
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, receipt)
	case "search":
		flags := flag.NewFlagSet("inventory search", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		mode := flags.String("mode", "browse", "")
		query := flags.String("query", "", "")
		scope := flags.String("scope", "", "")
		limit := flags.Int("limit", 50, "")
		cursor := flags.String("cursor", "", "")
		format := flags.String("format", "json", "")
		archived := flags.Bool("include-archived", false, "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || (*format != "json" && *format != "ndjson") {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "invalid inventory search flags", err))
		}
		if dependencies.InventorySearch == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory search is unavailable", nil))
		}
		page, err := dependencies.InventorySearch(ctx, inventory.SearchRequest{Mode: inventory.SearchMode(*mode), Query: *query, ScopeRoot: *scope, Limit: *limit, Cursor: *cursor, IncludeArchived: *archived})
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		if *format == "json" {
			return writeCommandJSON(streams, page)
		}
		encoder := json.NewEncoder(streams.stdout)
		for _, item := range page.Items {
			if err := encoder.Encode(item); err != nil {
				return diagnostic(streams.stderr, err)
			}
		}
		if page.NextCursor != "" {
			_, _ = fmt.Fprintln(streams.stderr, "next_cursor="+page.NextCursor)
		}
		return 0
	case "read", "archive", "delete":
		flags := flag.NewFlagSet("inventory "+args[0], flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		hostname := flags.String("hostname", "", "")
		archived := flags.Bool("archived", true, "")
		suppress := flags.Bool("suppress", false, "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *hostname == "" {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "inventory operation requires --hostname", err))
		}
		switch args[0] {
		case "read":
			if dependencies.InventoryRead == nil {
				return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory read is unavailable", nil))
			}
			asset, err := dependencies.InventoryRead(ctx, *hostname)
			if err != nil {
				return diagnostic(streams.stderr, err)
			}
			return writeCommandJSON(streams, asset)
		case "archive":
			if dependencies.InventoryArchive == nil {
				return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory archive is unavailable", nil))
			}
			asset, err := dependencies.InventoryArchive(ctx, *hostname, *archived)
			if err != nil {
				return diagnostic(streams.stderr, err)
			}
			return writeCommandJSON(streams, asset)
		default:
			if dependencies.InventoryDelete == nil {
				return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory delete is unavailable", nil))
			}
			generation, err := dependencies.InventoryDelete(ctx, *hostname, *suppress)
			if err != nil {
				return diagnostic(streams.stderr, err)
			}
			return writeCommandJSON(streams, struct {
				DeletionGeneration int64 `json:"deletion_generation"`
			}{generation})
		}
	case "backfill-ct":
		flags := flag.NewFlagSet("inventory backfill-ct", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		cursor := flags.String("cursor", "", "")
		limit := flags.Int("limit", 1000, "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "invalid inventory backfill flags", err))
		}
		if dependencies.InventoryBackfill == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory backfill is unavailable", nil))
		}
		page, err := dependencies.InventoryBackfill(ctx, *cursor, *limit)
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, page)
	default:
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "unknown inventory operation", nil))
	}
}
