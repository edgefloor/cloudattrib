package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"cloudattrib/internal/model"
)

// ClientConfig configures one explicit recursive resolver.
type ClientConfig struct {
	Resolver string
	Timeout  time.Duration
	Attempts int
}

// Client is a raw-record adapter around the pinned DNS library.
type Client struct {
	resolver string
	timeout  time.Duration
	attempts int
	now      func() time.Time
}

// NewClient validates an explicit resolver and bounded retry policy.
func NewClient(config ClientConfig) (*Client, error) {
	if _, _, err := net.SplitHostPort(config.Resolver); err != nil {
		return nil, fmt.Errorf("parse DNS resolver: %w", err)
	}
	if config.Timeout <= 0 || config.Attempts <= 0 {
		return nil, fmt.Errorf("DNS timeout and attempts must be positive")
	}
	return &Client{resolver: config.Resolver, timeout: config.Timeout, attempts: config.Attempts, now: time.Now}, nil
}

// Query sends one raw question to the configured resolver only.
func (c *Client) Query(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
	message := new(mdns.Msg)
	message.SetQuestion(mdns.Fqdn(question.Name), question.Type)
	var lastErr error
	for range c.attempts {
		response, transport, err := c.exchange(ctx, message)
		if err != nil {
			lastErr = err
			continue
		}
		return c.convert(question, response, transport)
	}
	return model.DNSResult{Question: question, Resolver: c.resolver}, fmt.Errorf("query DNS %s type %d: %w", question.Name, question.Type, lastErr)
}

func (c *Client) exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, string, error) {
	udp := &mdns.Client{Net: "udp", Timeout: c.timeout}
	response, _, err := udp.ExchangeContext(ctx, message, c.resolver)
	if err != nil {
		return nil, "udp", err
	}
	if !response.Truncated {
		return response, "udp", nil
	}
	tcp := &mdns.Client{Net: "tcp", Timeout: c.timeout}
	response, _, err = tcp.ExchangeContext(ctx, message, c.resolver)
	if err != nil {
		return nil, "tcp", err
	}
	return response, "tcp", nil
}

func (c *Client) convert(question model.DNSQuestion, response *mdns.Msg, transport string) (model.DNSResult, error) {
	result := model.DNSResult{
		Question:     question,
		ResponseCode: response.Rcode,
		Transport:    transport,
		Resolver:     c.resolver,
	}
	for index, record := range response.Answer {
		payload, address, ok := dnsPayload(record)
		if !ok {
			continue
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return model.DNSResult{}, fmt.Errorf("encode DNS record: %w", err)
		}
		result.Records = append(result.Records, model.Observation{
			ID:         observationID("dns-record", question.Name, fmt.Sprint(question.Type), fmt.Sprint(index), record.String()),
			Type:       "dns_record",
			Subject:    strings.TrimSuffix(strings.ToLower(record.Header().Name), "."),
			ObservedAt: c.now(),
			Status:     "answered",
			Payload:    encoded,
		})
		if address.IsValid() {
			result.Addresses = append(result.Addresses, address.Unmap())
		}
	}
	return result, nil
}

func dnsPayload(record mdns.RR) (model.DNSPayload, netip.Addr, bool) {
	header := record.Header()
	payload := model.DNSPayload{RRType: mdns.TypeToString[header.Rrtype], Owner: strings.TrimSuffix(strings.ToLower(header.Name), "."), TTL: header.Ttl}
	switch value := record.(type) {
	case *mdns.A:
		address, ok := netip.AddrFromSlice(value.A)
		if !ok {
			return model.DNSPayload{}, netip.Addr{}, false
		}
		payload.Address = address.Unmap()
		payload.Value = payload.Address.String()
		return payload, payload.Address, true
	case *mdns.AAAA:
		address, ok := netip.AddrFromSlice(value.AAAA)
		if !ok {
			return model.DNSPayload{}, netip.Addr{}, false
		}
		payload.Address = address.Unmap()
		payload.Value = payload.Address.String()
		return payload, payload.Address, true
	case *mdns.CNAME:
		payload.Value = strings.TrimSuffix(strings.ToLower(value.Target), ".")
	case *mdns.MX:
		payload.Value = fmt.Sprintf("%d %s", value.Preference, strings.TrimSuffix(strings.ToLower(value.Mx), "."))
	case *mdns.NS:
		payload.Value = strings.TrimSuffix(strings.ToLower(value.Ns), ".")
	case *mdns.TXT:
		payload.Value = strings.Join(value.Txt, "")
	default:
		return model.DNSPayload{}, netip.Addr{}, false
	}
	return payload, netip.Addr{}, true
}
