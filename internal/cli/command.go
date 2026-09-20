package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"cloudattrib/internal/app"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/model"
)

const maxJSONLRows = 1000

// Dependencies supplies application behavior and testable command streams.
type Dependencies struct {
	Analyzer  app.Analyzer
	Serve     func(context.Context) error
	CTImport  func(context.Context, io.Reader, []string) (int, error)
	CTCollect func(context.Context, string) (ctlog.Metrics, error)
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
}

// Run executes a command and returns its process exit status.
func Run(ctx context.Context, args []string, dependencies Dependencies) int {
	streams := normalizeStreams(dependencies)
	if len(args) == 0 {
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "a subcommand is required", nil))
	}
	switch args[0] {
	case "analyze":
		return runAnalyze(ctx, args[1:], dependencies, streams)
	case "batch":
		return runBatch(ctx, args[1:], dependencies, streams)
	case "lookup-ip":
		return runLookupIP(ctx, args[1:], dependencies, streams)
	case "reclassify":
		return runReclassify(ctx, args[1:], dependencies, streams)
	case "serve":
		if len(args) != 1 {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "serve does not accept positional arguments", nil))
		}
		if dependencies.Serve == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "service wiring is unavailable", nil))
		}
		if err := dependencies.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return diagnostic(streams.stderr, model.NewError(model.CodePersistenceUnavailable, "service stopped", err))
		}
		return 0
	case "ct":
		return runCT(ctx, args[1:], dependencies, streams)
	default:
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, fmt.Sprintf("unknown subcommand %q", args[0]), nil))
	}
}

func runCT(ctx context.Context, args []string, dependencies Dependencies, streams commandStreams) int {
	if len(args) == 0 {
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "ct requires import or collect", nil))
	}
	switch args[0] {
	case "import":
		flags := flag.NewFlagSet("ct import", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		input := flags.String("input", "", "")
		scope := flags.String("scope", "", "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *input == "" || *scope == "" {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "ct import requires --input and --scope", err))
		}
		if dependencies.CTImport == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "CT import wiring is unavailable", nil))
		}
		reader := streams.stdin
		if *input != "-" {
			file, err := os.Open(*input)
			if err != nil {
				return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "open CT input", err))
			}
			defer func() { _ = file.Close() }()
			reader = file
		}
		roots := strings.Split(*scope, ",")
		count, err := dependencies.CTImport(ctx, reader, roots)
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, struct {
			Imported int `json:"imported"`
		}{Imported: count})
	case "collect":
		flags := flag.NewFlagSet("ct collect", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		configuration := flags.String("config", "", "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *configuration == "" {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "ct collect requires --config", err))
		}
		if dependencies.CTCollect == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "CT collection wiring is unavailable", nil))
		}
		metrics, err := dependencies.CTCollect(ctx, *configuration)
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, metrics)
	default:
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, fmt.Sprintf("unknown ct subcommand %q", args[0]), nil))
	}
}

func writeCommandJSON(streams commandStreams, value any) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		return diagnostic(streams.stderr, err)
	}
	if _, err := fmt.Fprintln(streams.stdout, string(encoded)); err != nil {
		return diagnostic(streams.stderr, err)
	}
	return 0
}

func runBatch(ctx context.Context, args []string, d Dependencies, s commandStreams) int {
	flags := flag.NewFlagSet("batch", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "")
	format := flags.String("format", "jsonl", "")
	kind := flags.String("kind", "domain", "")
	mode := flags.String("mode", "full", "")
	unordered := flags.Bool("unordered", false, "")
	if err := flags.Parse(args); err != nil {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, err.Error(), err))
	}
	if flags.NArg() != 0 || *input == "" || *format != "jsonl" {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, "batch requires --input and --format jsonl", nil))
	}
	if err := requireAnalyzer(d.Analyzer); err != nil {
		return diagnostic(s.stderr, err)
	}
	reader := s.stdin
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, "open input: "+err.Error(), err))
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	requests := make([]model.AnalyzeRequest, 0)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target == "" {
			continue
		}
		if len(requests) >= maxJSONLRows {
			return diagnostic(s.stderr, model.NewError(model.CodeInputTooLarge, "batch input exceeds 1000 rows", nil))
		}
		requests = append(requests, model.AnalyzeRequest{Target: target, Kind: model.TargetKind(*kind), Mode: model.Mode(*mode)})
	}
	if err := scanner.Err(); err != nil {
		return diagnostic(s.stderr, model.NewError(model.CodeInputTooLarge, "read batch input", err))
	}
	if !*unordered {
		return emitOrderedBatch(ctx, requests, d.Analyzer, s)
	}
	return emitUnorderedBatch(ctx, requests, d.Analyzer, s)
}

func emitOrderedBatch(ctx context.Context, requests []model.AnalyzeRequest, analyzer app.Analyzer, streams commandStreams) int {
	exit := 0
	for index, request := range requests {
		item, rowExit := analyzeEnvelope(ctx, analyzer, index, request)
		if err := writeEnvelope(streams.stdout, item); err != nil {
			return diagnostic(streams.stderr, err)
		}
		exit = combineExit(exit, rowExit)
	}
	return exit
}

func emitUnorderedBatch(ctx context.Context, requests []model.AnalyzeRequest, analyzer app.Analyzer, streams commandStreams) int {
	type job struct {
		index   int
		request model.AnalyzeRequest
	}
	type outcome struct {
		item envelope
		exit int
	}
	jobs := make(chan job)
	results := make(chan outcome)
	workers := 4
	if len(requests) < workers {
		workers = len(requests)
	}
	for range workers {
		go func() {
			for queued := range jobs {
				item, rowExit := analyzeEnvelope(ctx, analyzer, queued.index, queued.request)
				results <- outcome{item: item, exit: rowExit}
			}
		}()
	}
	go func() {
		for index, request := range requests {
			jobs <- job{index: index, request: request}
		}
		close(jobs)
	}()
	exit := 0
	for range requests {
		result := <-results
		if err := writeEnvelope(streams.stdout, result.item); err != nil {
			return diagnostic(streams.stderr, err)
		}
		exit = combineExit(exit, result.exit)
	}
	return exit
}

func analyzeEnvelope(ctx context.Context, analyzer app.Analyzer, index int, request model.AnalyzeRequest) (envelope, int) {
	report, err := analyzer.Analyze(ctx, request)
	if err != nil {
		return envelope{InputIndex: index, Error: externalError(err)}, model.CLIExit(err)
	}
	_, exit, err := RenderReport(report)
	if err != nil {
		return envelope{InputIndex: index, Error: externalError(err)}, model.CLIExit(err)
	}
	return envelope{InputIndex: index, Result: report}, exit
}

func writeEnvelope(writer io.Writer, item envelope) error {
	encoded, err := json.Marshal(item)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(writer, string(encoded))
	return err
}

type commandStreams struct {
	stdin          io.Reader
	stdout, stderr io.Writer
}

func normalizeStreams(d Dependencies) commandStreams {
	in := d.Stdin
	if in == nil {
		in = os.Stdin
	}
	out := d.Stdout
	if out == nil {
		out = os.Stdout
	}
	errOut := d.Stderr
	if errOut == nil {
		errOut = os.Stderr
	}
	return commandStreams{in, out, errOut}
}
func requireAnalyzer(analyzer app.Analyzer) error {
	if analyzer == nil {
		return model.NewError(model.CodeCapabilityUnavailable, "CLI application wiring is unavailable", nil)
	}
	return nil
}
func runAnalyze(ctx context.Context, args []string, d Dependencies, s commandStreams) int {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kind := flags.String("kind", "domain", "")
	mode := flags.String("mode", "full", "")
	format := flags.String("format", "json", "")
	input := flags.String("input", "", "")
	unordered := flags.Bool("unordered", false, "")
	ct := flags.Bool("ct", false, "")
	if err := flags.Parse(reorderFlags(args, map[string]bool{"kind": true, "mode": true, "format": true, "input": true, "ct": false, "unordered": false})); err != nil {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, err.Error(), err))
	}
	if *format != "json" && *format != "jsonl" {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidOptions, "format must be json or jsonl", nil))
	}
	if err := requireAnalyzer(d.Analyzer); err != nil {
		return diagnostic(s.stderr, err)
	}
	if *input != "" {
		if *format != "jsonl" {
			return diagnostic(s.stderr, model.NewError(model.CodeInvalidOptions, "JSONL input requires --format jsonl", nil))
		}
		_ = unordered
		return runJSONL(ctx, *input, d.Analyzer, s)
	}
	if flags.NArg() != 1 {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, "analyze requires one target", nil))
	}
	report, err := d.Analyzer.Analyze(ctx, model.AnalyzeRequest{Target: flags.Arg(0), Kind: model.TargetKind(*kind), Mode: model.Mode(*mode), CTDiscovery: *ct})
	if err != nil {
		return diagnostic(s.stderr, err)
	}
	encoded, exit, err := RenderReport(report)
	if err != nil {
		return diagnostic(s.stderr, err)
	}
	if _, err := fmt.Fprintln(s.stdout, string(encoded)); err != nil {
		return diagnostic(s.stderr, err)
	}
	return exit
}

type envelope struct {
	InputIndex int          `json:"input_index"`
	Result     any          `json:"result,omitempty"`
	Error      *outputError `json:"error,omitempty"`
}
type outputError struct {
	Code    model.ErrorCode `json:"code"`
	Message string          `json:"message"`
}

func runJSONL(ctx context.Context, path string, analyzer app.Analyzer, s commandStreams) int {
	reader := s.stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, "open input: "+err.Error(), err))
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	exit, index := 0, 0
	for scanner.Scan() {
		if index >= maxJSONLRows {
			return diagnostic(s.stderr, model.NewError(model.CodeInputTooLarge, "JSONL input exceeds 1000 rows", nil))
		}
		var request model.AnalyzeRequest
		var item envelope
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			item = envelope{InputIndex: index, Error: externalError(model.NewError(model.CodeInvalidSyntax, "invalid JSONL input", err))}
			exit = combineExit(exit, 2)
		} else if report, err := analyzer.Analyze(ctx, request); err != nil {
			item = envelope{InputIndex: index, Error: externalError(err)}
			exit = combineExit(exit, model.CLIExit(err))
		} else {
			item = envelope{InputIndex: index, Result: report}
			_, rowExit, err := RenderReport(report)
			if err != nil {
				return diagnostic(s.stderr, err)
			}
			exit = combineExit(exit, rowExit)
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return diagnostic(s.stderr, err)
		}
		if _, err := fmt.Fprintln(s.stdout, string(encoded)); err != nil {
			return diagnostic(s.stderr, err)
		}
		index++
	}
	if err := scanner.Err(); err != nil {
		return diagnostic(s.stderr, model.NewError(model.CodeInputTooLarge, "read JSONL input", err))
	}
	return exit
}
func runLookupIP(ctx context.Context, args []string, d Dependencies, s commandStreams) int {
	flags := flag.NewFlagSet("lookup-ip", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	match := flags.String("match", "all", "")
	if err := flags.Parse(reorderFlags(args, map[string]bool{"match": true})); err != nil {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, err.Error(), err))
	}
	if flags.NArg() != 1 {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, "lookup-ip requires one IP address", nil))
	}
	address, err := netip.ParseAddr(flags.Arg(0))
	if err != nil {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidTarget, "lookup-ip requires a valid IP address", err))
	}
	if err := requireAnalyzer(d.Analyzer); err != nil {
		return diagnostic(s.stderr, err)
	}
	result, err := d.Analyzer.LookupIP(ctx, model.IPLookupRequest{Address: address.Unmap(), Match: *match})
	if err != nil {
		return diagnostic(s.stderr, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return diagnostic(s.stderr, err)
	}
	if _, err = fmt.Fprintln(s.stdout, string(encoded)); err != nil {
		return diagnostic(s.stderr, err)
	}
	if result.Status == model.StatusComplete {
		return 0
	}
	return 3
}
func runReclassify(ctx context.Context, args []string, d Dependencies, s commandStreams) int {
	flags := flag.NewFlagSet("reclassify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	reportID := flags.String("report", "", "")
	bundle := flags.String("bundle", "", "")
	if err := flags.Parse(args); err != nil {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, err.Error(), err))
	}
	if flags.NArg() != 0 || *reportID == "" || *bundle == "" {
		return diagnostic(s.stderr, model.NewError(model.CodeInvalidSyntax, "reclassify requires --report and --bundle", nil))
	}
	if err := requireAnalyzer(d.Analyzer); err != nil {
		return diagnostic(s.stderr, err)
	}
	report, err := d.Analyzer.Reclassify(ctx, model.ReclassifyRequest{ReportID: *reportID, BundleID: *bundle})
	if err != nil {
		return diagnostic(s.stderr, err)
	}
	encoded, exit, err := RenderReport(report)
	if err != nil {
		return diagnostic(s.stderr, err)
	}
	if _, err = fmt.Fprintln(s.stdout, string(encoded)); err != nil {
		return diagnostic(s.stderr, err)
	}
	return exit
}
func externalError(err error) *outputError {
	return &outputError{Code: model.ErrorCodeOf(err), Message: err.Error()}
}
func diagnostic(writer io.Writer, err error) int {
	_, _ = fmt.Fprintf(writer, "cloudattrib: %s\n", err)
	return model.CLIExit(err)
}
func combineExit(current, next int) int {
	if current == 4 || next == 4 {
		return 4
	}
	if current == 3 || next == 3 {
		return 3
	}
	if current == 2 || next == 2 {
		return 2
	}
	return 0
}

func reorderFlags(args []string, needsValue map[string]bool) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if len(argument) < 3 || argument[:2] != "--" {
			positionals = append(positionals, argument)
			continue
		}
		flags = append(flags, argument)
		name := argument[2:]
		if equals := strings.IndexByte(name, '='); equals >= 0 {
			name = name[:equals]
		}
		if needsValue[name] && !strings.Contains(argument, "=") && index+1 < len(args) {
			index++
			flags = append(flags, args[index])
		}
	}
	return append(flags, positionals...)
}
