package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

// ClientConfig configures one explicit recursive resolver.
type ClientConfig struct {
	Resolver        string
	Network         string
	Timeout         time.Duration
	Attempts        int
	CNAMEChainDepth int
}

// Client is a raw-record adapter around the pinned DNS library.
type Client struct {
	resolver        string
	network         string
	timeout         time.Duration
	attempts        int
	cnameChainDepth int
	now             func() time.Time
}

// NewClient validates an explicit resolver and bounded retry policy.
func NewClient(config ClientConfig) (*Client, error) {
	if _, _, err := net.SplitHostPort(config.Resolver); err != nil {
		return nil, fmt.Errorf("parse DNS resolver: %w", err)
	}
	if config.Timeout <= 0 || config.Attempts <= 0 {
		return nil, fmt.Errorf("DNS timeout and attempts must be positive")
	}
	network := config.Network
	if network == "" {
		network = "udp"
	}
	if network != "udp" && network != "tcp" {
		return nil, fmt.Errorf("DNS network must be udp or tcp")
	}
	cnameChainDepth := config.CNAMEChainDepth
	if cnameChainDepth <= 0 {
		cnameChainDepth = 16
	}
	return &Client{resolver: config.Resolver, network: network, timeout: config.Timeout, attempts: config.Attempts, cnameChainDepth: cnameChainDepth, now: time.Now}, nil
}

// Query sends one raw question to the configured resolver only.
func (c *Client) Query(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
	message := new(mdns.Msg)
	message.SetQuestion(mdns.Fqdn(question.Name), question.Type)
	var lastErr error
	for attempt := 1; attempt <= c.attempts; attempt++ {
		response, transport, err := c.exchange(ctx, message)
		if err != nil {
			if model.ErrorCodeOf(err) == model.CodeBudgetExceeded || model.ErrorCodeOf(err) == model.CodeCancelled {
				return model.DNSResult{Question: question, Attempt: attempt, Resolver: c.resolver, Outcome: outcomeForError(err)}, err
			}
			if ctx.Err() != nil {
				return model.DNSResult{Question: question, Attempt: attempt, Resolver: c.resolver, Outcome: outcomeForError(ctx.Err())}, ctx.Err()
			}
			lastErr = err
			continue
		}
		result, err := c.convert(question, response, transport)
		result.Attempt = attempt
		if result.Outcome == model.DNSOutcomeSERVFAIL && attempt < c.attempts {
			continue
		}
		return result, err
	}
	result := model.DNSResult{Question: question, Attempt: c.attempts, Resolver: c.resolver, Outcome: outcomeForError(lastErr)}
	return result, fmt.Errorf("query DNS %s type %d: %w", question.Name, question.Type, lastErr)
}

func (c *Client) exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, string, error) {
	if c.network == "tcp" {
		tcp := &mdns.Client{Net: "tcp", Timeout: c.timeout}
		response, err := c.exchangeAttempt(ctx, tcp, message)
		return response, "tcp", err
	}
	udp := &mdns.Client{Net: "udp", Timeout: c.timeout}
	response, err := c.exchangeAttempt(ctx, udp, message)
	if err != nil {
		return nil, "udp", err
	}
	if !response.Truncated {
		return response, "udp", nil
	}
	tcp := &mdns.Client{Net: "tcp", Timeout: c.timeout}
	response, err = c.exchangeAttempt(ctx, tcp, message)
	if err != nil {
		return nil, "tcp", err
	}
	return response, "tcp", nil
}

func (c *Client) exchangeAttempt(ctx context.Context, client *mdns.Client, message *mdns.Msg) (*mdns.Msg, error) {
	release, err := policy.AcquireDNS(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	response, _, err := client.ExchangeContext(ctx, message, c.resolver)
	return response, err
}

func (c *Client) convert(question model.DNSQuestion, response *mdns.Msg, transport string) (model.DNSResult, error) {
	result := model.DNSResult{
		Question:     question,
		ResponseCode: response.Rcode,
		Outcome:      outcomeForResponse(response),
		Transport:    transport,
		Resolver:     c.resolver,
	}
	cnameCount := 0
	for _, record := range response.Answer {
		if record.Header().Rrtype == mdns.TypeCNAME {
			if cnameCount >= c.cnameChainDepth {
				result.Omitted++
				continue
			}
			cnameCount++
		}
		payload, address, ok := dnsPayload(record)
		if !ok {
			continue
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return model.DNSResult{}, fmt.Errorf("encode DNS record: %w", err)
		}
		result.Records = append(result.Records, model.Observation{
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

func outcomeForResponse(response *mdns.Msg) model.DNSOutcome {
	switch response.Rcode {
	case mdns.RcodeSuccess:
		if len(response.Answer) == 0 {
			return model.DNSOutcomeNoData
		}
		return model.DNSOutcomeAnswered
	case mdns.RcodeNameError:
		return model.DNSOutcomeNXDomain
	case mdns.RcodeServerFailure:
		return model.DNSOutcomeSERVFAIL
	case mdns.RcodeRefused:
		return model.DNSOutcomeRefused
	default:
		return model.DNSOutcomeFailed
	}
}

func outcomeForError(err error) model.DNSOutcome {
	if err == nil {
		return model.DNSOutcomeFailed
	}
	switch model.ErrorCodeOf(err) {
	case model.CodeBudgetExceeded:
		return model.DNSOutcomeBudgetExhausted
	case model.CodeCancelled:
		return model.DNSOutcomeCancelled
	}
	if errors.Is(err, context.Canceled) {
		return model.DNSOutcomeCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.DNSOutcomeTimeout
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return model.DNSOutcomeTimeout
	}
	return model.DNSOutcomeFailed
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
