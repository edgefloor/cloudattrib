// Package target normalizes caller input and plans the initial target scope.
package target

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"cloudattrib/internal/model"
)

const (
	maxDomainInput = 1024
	maxURLInput    = 8192
	idnaVersion    = "golang.org/x/net/idna@v0.58.0/lookup"
	pslVersion     = "golang.org/x/net/publicsuffix@v0.58.0"
)

// Normalize validates input before collection and returns a bounded seed plan.
func Normalize(req model.AnalyzeRequest) (model.NormalizedRequest, error) {
	if !utf8.ValidString(req.Target) || containsControl(req.Target) {
		return model.NormalizedRequest{}, invalidTarget("target contains invalid text")
	}
	mode := req.Mode
	if mode == "" {
		if req.Kind == model.TargetIP {
			mode = model.ModeIP
		} else {
			mode = model.ModeFull
		}
	}

	result := model.NormalizedRequest{
		Mode:                mode,
		OrganizationLabel:   req.OrganizationLabel,
		CTDiscovery:         req.CTDiscovery,
		IDNAProfileVersion:  idnaVersion,
		PublicSuffixVersion: pslVersion,
	}

	switch req.Kind {
	case model.TargetDomain:
		name, err := normalizeDomain(req.Target)
		if err != nil {
			return model.NormalizedRequest{}, err
		}
		if mode != model.ModeFull && mode != model.ModeDNS {
			return model.NormalizedRequest{}, invalidOptions("domain target requires full or dns mode")
		}
		result.Target = model.Target{Original: req.Target, Canonical: name, Kind: model.TargetDomain}
		result.SeedHostnames = []string{name}
		registrable, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			return model.NormalizedRequest{}, invalidTarget("domain must be below a public suffix")
		}
		if req.IncludeWWW && name == registrable {
			result.SeedHostnames = append(result.SeedHostnames, "www."+name)
		}
	case model.TargetURL:
		normalizedURL, hostname, err := normalizeURL(req.Target)
		if err != nil {
			return model.NormalizedRequest{}, err
		}
		if mode != model.ModeFull && mode != model.ModeDNS {
			return model.NormalizedRequest{}, invalidOptions("URL target requires full or dns mode")
		}
		result.Target = model.Target{Original: req.Target, Canonical: normalizedURL, Kind: model.TargetURL}
		result.SeedHostnames = []string{hostname}
	case model.TargetIP:
		address, err := normalizeIP(req.Target)
		if err != nil {
			return model.NormalizedRequest{}, err
		}
		if mode != model.ModeIP {
			return model.NormalizedRequest{}, invalidOptions("IP target requires ip mode")
		}
		if len(req.AdditionalHostnames) != 0 || len(req.ScopeRoots) != 0 || req.CTDiscovery {
			return model.NormalizedRequest{}, invalidOptions("IP target cannot request live collection scope")
		}
		result.Target = model.Target{Original: req.Target, Canonical: address.String(), Kind: model.TargetIP}
		return result, nil
	default:
		return model.NormalizedRequest{}, invalidTarget("unsupported target kind")
	}

	scopeRoots, err := normalizeScopeRoots(req.ScopeRoots, result.SeedHostnames[0])
	if err != nil {
		return model.NormalizedRequest{}, err
	}
	result.ScopeRoots = scopeRoots
	for _, additional := range req.AdditionalHostnames {
		name, normalizeErr := normalizeDomain(additional)
		if normalizeErr != nil {
			return model.NormalizedRequest{}, fmt.Errorf("normalize additional hostname: %w", normalizeErr)
		}
		if !withinAnyScope(name, scopeRoots) {
			return model.NormalizedRequest{}, invalidOptions("additional hostname is outside the declared scope")
		}
		result.SeedHostnames = append(result.SeedHostnames, name)
	}
	slices.Sort(result.SeedHostnames)
	result.SeedHostnames = slices.Compact(result.SeedHostnames)
	return result, nil
}

func normalizeDomain(input string) (string, error) {
	if input == "" || len(input) > maxDomainInput {
		return "", invalidTarget("domain length is invalid")
	}
	input = strings.TrimSuffix(input, ".")
	if input == "" || strings.HasSuffix(input, ".") {
		return "", invalidTarget("domain has invalid terminal dots")
	}
	ascii, err := idna.Lookup.ToASCII(input)
	if err != nil {
		return "", model.NewError(model.CodeInvalidTarget, "domain is not valid IDNA", err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 || !validDNSName(ascii) {
		return "", invalidTarget("domain is not a valid DNS name")
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(ascii); err != nil {
		return "", invalidTarget("domain must be below a public suffix")
	}
	return ascii, nil
}

func normalizeURL(input string) (string, string, error) {
	if input == "" || len(input) > maxURLInput {
		return "", "", invalidTarget("URL length is invalid")
	}
	parsed, err := url.Parse(input)
	if err != nil {
		return "", "", model.NewError(model.CodeInvalidTarget, "URL is invalid", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", invalidTarget("URL scheme must be http or https")
	}
	if parsed.User != nil {
		return "", "", invalidTarget("URL userinfo is not allowed")
	}
	if parsed.Fragment != "" {
		return "", "", invalidTarget("URL fragments are not allowed")
	}
	if parsed.Hostname() == "" {
		return "", "", invalidTarget("URL hostname is required")
	}
	port := parsed.Port()
	if port != "" && port != "80" && port != "443" {
		return "", "", invalidTarget("URL port must be 80 or 443")
	}

	hostname := parsed.Hostname()
	if address, parseErr := netip.ParseAddr(hostname); parseErr == nil {
		if address.Zone() != "" {
			return "", "", invalidTarget("URL address zones are not allowed")
		}
		hostname = address.Unmap().String()
		if address.Unmap().Is6() {
			parsed.Host = "[" + hostname + "]"
		} else {
			parsed.Host = hostname
		}
		if port != "" {
			parsed.Host = net.JoinHostPort(hostname, port)
		}
	} else {
		canonicalHost, normalizeErr := normalizeDomain(hostname)
		if normalizeErr != nil {
			return "", "", normalizeErr
		}
		hostname = canonicalHost
		parsed.Host = hostname
		if port != "" {
			parsed.Host = net.JoinHostPort(hostname, port)
		}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	return parsed.String(), hostname, nil
}

func normalizeIP(input string) (netip.Addr, error) {
	address, err := netip.ParseAddr(input)
	if err != nil {
		return netip.Addr{}, model.NewError(model.CodeInvalidTarget, "IP address is invalid", err)
	}
	if address.Zone() != "" {
		return netip.Addr{}, invalidTarget("IP address zones are not allowed")
	}
	return address.Unmap(), nil
}

func normalizeScopeRoots(values []string, seed string) ([]string, error) {
	if len(values) == 0 {
		if _, err := netip.ParseAddr(seed); err == nil {
			return []string{seed}, nil
		}
		root, err := publicsuffix.EffectiveTLDPlusOne(seed)
		if err != nil {
			return nil, invalidTarget("scope root cannot be derived")
		}
		return []string{root}, nil
	}
	roots := make([]string, 0, len(values))
	for _, value := range values {
		root, err := normalizeDomain(value)
		if err != nil {
			return nil, fmt.Errorf("normalize scope root: %w", err)
		}
		roots = append(roots, root)
	}
	slices.Sort(roots)
	return slices.Compact(roots), nil
}

func withinAnyScope(name string, roots []string) bool {
	for _, root := range roots {
		if name == root || strings.HasSuffix(name, "."+root) {
			return true
		}
	}
	return false
}

func validDNSName(name string) bool {
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func invalidTarget(message string) error {
	return model.NewError(model.CodeInvalidTarget, message, nil)
}

func invalidOptions(message string) error {
	return model.NewError(model.CodeInvalidOptions, message, nil)
}
