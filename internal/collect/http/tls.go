package http

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"cloudattrib/internal/model"
)

const maximumTLSNames = 64
const maximumTLSFieldBytes = 255
const maximumIssuerOrganizations = 4

type handshakeCapture struct {
	mu    sync.Mutex
	seen  bool
	state tls.ConnectionState
	err   error
}

func (c *handshakeCapture) record(state tls.ConnectionState, err error) {
	c.mu.Lock()
	c.seen, c.state, c.err = true, state, err
	c.mu.Unlock()
}

func (c *handshakeCapture) observation(targetURL *url.URL, address netip.Addr, originalHostname string, occurrence model.ObservationOccurrence, now func() time.Time) (model.Observation, bool) {
	c.mu.Lock()
	seen, state, handshakeErr := c.seen, c.state, c.err
	c.mu.Unlock()
	if !seen {
		return model.Observation{}, false
	}
	payload := model.TLSCertificatePayload{
		URL: targetURL.Scheme + "://" + targetURL.Host, Hostname: targetURL.Hostname(), PeerAddress: address,
		CollectionRunID: occurrence.CollectionRunID, Attempt: occurrence.Attempt, Hop: occurrence.Hop,
		Verified:   handshakeErr == nil && len(state.PeerCertificates) > 0,
		TLSVersion: tls.VersionName(state.Version),
	}
	bounded := func(value string) string {
		if len(value) > maximumTLSFieldBytes {
			payload.FieldsTruncated++
		}
		return boundedTLSField(value)
	}
	payload.ALPN = bounded(state.NegotiatedProtocol)
	if !payload.Verified {
		payload.Failure = tlsFailureCode(handshakeErr)
		if handshakeErr == nil {
			payload.Failure = "certificate_missing"
		}
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		digest := sha256.Sum256(leaf.Raw)
		payload.FingerprintSHA256 = "sha256:" + hex.EncodeToString(digest[:])
		payload.SubjectCommonName = bounded(leaf.Subject.CommonName)
		payload.IssuerCommonName = bounded(leaf.Issuer.CommonName)
		for _, organization := range leaf.Issuer.Organization {
			if len(payload.IssuerOrganization) == maximumIssuerOrganizations {
				break
			}
			payload.IssuerOrganization = append(payload.IssuerOrganization, bounded(organization))
		}
		for _, name := range leaf.DNSNames {
			if len(payload.DNSNames)+len(payload.IPAddresses) == maximumTLSNames {
				payload.NamesOmitted++
				continue
			}
			payload.DNSNames = append(payload.DNSNames, bounded(name))
		}
		for _, address := range leaf.IPAddresses {
			if len(payload.DNSNames)+len(payload.IPAddresses) == maximumTLSNames {
				payload.NamesOmitted++
				continue
			}
			payload.IPAddresses = append(payload.IPAddresses, address.String())
		}
		if len(leaf.Issuer.Organization) > maximumIssuerOrganizations {
			payload.FieldsTruncated += len(leaf.Issuer.Organization) - maximumIssuerOrganizations
		}
		before, after := leaf.NotBefore, leaf.NotAfter
		payload.NotBefore, payload.NotAfter = &before, &after
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return model.Observation{}, false
	}
	scope := model.ScopeRoot
	if !strings.EqualFold(targetURL.Hostname(), originalHostname) {
		scope = model.ScopeExternalRedirect
	}
	status := "verified"
	if !payload.Verified {
		status = "unverified"
	}
	return model.Observation{
		ID:   model.ObservationID("tls-certificate", occurrence, targetURL.Scheme, targetURL.Host, address.String()),
		Type: "tls_certificate", Subject: targetURL.Hostname(), Relation: model.RelationWebDelivery, Scope: scope,
		ObservedAt: now(), Status: status, Payload: encoded, ContentHash: payload.FingerprintSHA256,
	}, true
}

func tlsFailureCode(err error) string {
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "hostname_mismatch"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return "certificate_expired_or_not_yet_valid"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "untrusted_authority"
	}
	return "handshake_failed"
}

func boundedTLSField(value string) string {
	if len(value) > maximumTLSFieldBytes {
		value = value[:maximumTLSFieldBytes]
	}
	return strings.ToValidUTF8(value, "")
}
