package dns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestClientCountsActualAttemptsAgainstExecutionBudget(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int64
	server := &mdns.Server{PacketConn: packetConn, Handler: mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		queries.Add(1)
		response := new(mdns.Msg)
		response.SetReply(request)
		if writeErr := writer.WriteMsg(response); writeErr != nil {
			t.Errorf("WriteMsg() error = %v", writeErr)
		}
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.ShutdownContext(shutdownCtx)
	})

	limits := policy.DefaultLimits()
	limits.DNSQuestions = 1
	controller, err := policy.NewController(limits, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, release, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	client, err := NewClient(ClientConfig{Resolver: packetConn.LocalAddr().String(), Network: "udp", Timeout: time.Second, Attempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	question := model.DNSQuestion{Name: "example.com", Type: mdns.TypeA}
	if _, err := client.Query(ctx, question); err != nil {
		t.Fatalf("first Query() error = %v", err)
	}
	second, err := client.Query(ctx, question)
	if model.ErrorCodeOf(err) != model.CodeBudgetExceeded {
		t.Fatalf("second Query() error = %v", err)
	}
	if second.Attempt != 0 {
		t.Fatalf("second Query() attempts = %d, want 0 network attempts", second.Attempt)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("DNS queries = %d, want 1", got)
	}
}

func TestClientRetriesSERVFAILWithinConfiguredAttempts(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int64
	server := &mdns.Server{PacketConn: packetConn, Handler: mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		if queries.Add(1) == 1 {
			response.Rcode = mdns.RcodeServerFailure
		} else {
			response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")}}
		}
		if writeErr := writer.WriteMsg(response); writeErr != nil {
			t.Errorf("WriteMsg() error = %v", writeErr)
		}
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.ShutdownContext(shutdownCtx)
	})

	client, err := NewClient(ClientConfig{Resolver: packetConn.LocalAddr().String(), Network: "udp", Timeout: time.Second, Attempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Query(t.Context(), model.DNSQuestion{Name: "example.com", Type: mdns.TypeA})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if result.Attempt != 2 || len(result.Addresses) != 1 || queries.Load() != 2 {
		t.Fatalf("Query() result = %#v, queries = %d", result, queries.Load())
	}
}

func TestClientDoesNotRetryCallerCancellation(t *testing.T) {
	t.Parallel()

	client, err := NewClient(ClientConfig{Resolver: "127.0.0.1:53", Network: "udp", Timeout: time.Second, Attempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := client.Query(ctx, model.DNSQuestion{Name: "example.com", Type: mdns.TypeA})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Query() error = %v", err)
	}
	if result.Attempt != 0 || result.Outcome != model.DNSOutcomeCancelled {
		t.Fatalf("Query() result = %#v", result)
	}
}

func TestClientUsesConfiguredResolverAndRetriesTruncatedUDPOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	address := listener.Addr().String()
	packetConn, err := net.ListenPacket("udp", address)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("listen UDP: %v", err)
	}
	handler := mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		if writer.LocalAddr().Network() == "udp" {
			response.Truncated = true
		} else {
			response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")}}
		}
		if writeErr := writer.WriteMsg(response); writeErr != nil {
			t.Errorf("WriteMsg() error = %v", writeErr)
		}
	})
	udpServer := &mdns.Server{PacketConn: packetConn, Handler: handler}
	tcpServer := &mdns.Server{Listener: listener, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = udpServer.ShutdownContext(shutdownCtx)
		_ = tcpServer.ShutdownContext(shutdownCtx)
	})

	client, err := NewClient(ClientConfig{Resolver: address, Timeout: time.Second, Attempts: 1})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	result, err := client.Query(context.Background(), model.DNSQuestion{Name: "example.com", Type: mdns.TypeA})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if result.Transport != "tcp" || result.Attempt != 2 || len(result.Addresses) != 1 || result.Addresses[0].String() != "93.184.216.34" {
		t.Fatalf("Query() result = %#v", result)
	}
}

func TestClientCanUseConfiguredTCPWithoutUDP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	server := &mdns.Server{Listener: listener, Handler: mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")}}
		if writeErr := writer.WriteMsg(response); writeErr != nil {
			t.Errorf("WriteMsg() error = %v", writeErr)
		}
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.ShutdownContext(shutdownCtx)
	})

	client, err := NewClient(ClientConfig{Resolver: listener.Addr().String(), Network: "tcp", Timeout: time.Second, Attempts: 1})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	result, err := client.Query(context.Background(), model.DNSQuestion{Name: "example.com", Type: mdns.TypeA})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if result.Transport != "tcp" || len(result.Addresses) != 1 {
		t.Fatalf("Query() result = %#v", result)
	}
}

func TestDNSPayloadJoinsTXTChunksWithinOneRecord(t *testing.T) {
	t.Parallel()

	payload, _, ok := dnsPayload(&mdns.TXT{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 30}, Txt: []string{"v=spf1 ", "include:_spf.example.net"}})
	if !ok || payload.Value != "v=spf1 include:_spf.example.net" {
		t.Fatalf("dnsPayload() = %#v, %t", payload, ok)
	}
}

func TestClientBoundsCNAMEChainRecords(t *testing.T) {
	t.Parallel()

	client := &Client{resolver: "fixture", cnameChainDepth: 1, now: time.Now}
	response := new(mdns.Msg)
	response.Answer = []mdns.RR{
		&mdns.CNAME{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeCNAME}, Target: "one.example.net."},
		&mdns.CNAME{Hdr: mdns.RR_Header{Name: "one.example.net.", Rrtype: mdns.TypeCNAME}, Target: "two.example.net."},
	}
	result, err := client.convert(model.DNSQuestion{Name: "example.com", Type: mdns.TypeCNAME}, response, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 || result.Omitted != 1 {
		t.Fatalf("convert() result = %#v", result)
	}
}

func TestConvertClassifiesDNSProtocolOutcomes(t *testing.T) {
	t.Parallel()

	client := &Client{resolver: "fixture", cnameChainDepth: 16, now: time.Now}
	tests := []struct {
		name    string
		rcode   int
		answers []mdns.RR
		want    model.DNSOutcome
	}{
		{name: "nodata", rcode: mdns.RcodeSuccess, want: model.DNSOutcomeNoData},
		{name: "answered", rcode: mdns.RcodeSuccess, answers: []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA}, A: net.ParseIP("93.184.216.34")}}, want: model.DNSOutcomeAnswered},
		{name: "nxdomain", rcode: mdns.RcodeNameError, want: model.DNSOutcomeNXDomain},
		{name: "servfail", rcode: mdns.RcodeServerFailure, want: model.DNSOutcomeSERVFAIL},
		{name: "refused", rcode: mdns.RcodeRefused, want: model.DNSOutcomeRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := new(mdns.Msg)
			response.Rcode = tt.rcode
			response.Answer = tt.answers
			result, err := client.convert(model.DNSQuestion{Name: "example.com", Type: mdns.TypeA}, response, "udp")
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != tt.want || result.ResponseCode != tt.rcode {
				t.Fatalf("convert() = %#v", result)
			}
		})
	}
}
