package dns

import (
	"context"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"cloudattrib/internal/model"
)

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

func TestDNSPayloadJoinsTXTChunksWithinOneRecord(t *testing.T) {
	t.Parallel()

	payload, _, ok := dnsPayload(&mdns.TXT{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 30}, Txt: []string{"v=spf1 ", "include:_spf.example.net"}})
	if !ok || payload.Value != "v=spf1 include:_spf.example.net" {
		t.Fatalf("dnsPayload() = %#v, %t", payload, ok)
	}
}
