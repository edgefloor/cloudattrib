package dns

import (
	"context"
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
	if _, err := client.Query(ctx, question); model.ErrorCodeOf(err) != model.CodeBudgetExceeded {
		t.Fatalf("second Query() error = %v", err)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("DNS queries = %d, want 1", got)
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
	if result.Transport != "tcp" || len(result.Addresses) != 1 || result.Addresses[0].String() != "93.184.216.34" {
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
