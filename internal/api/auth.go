package api

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const defaultIdentityHeader = "X-Cloudattrib-Operator"

// AuthenticationMode selects the configured trusted-operator identity source.
type AuthenticationMode string

// Authentication mode values keep the API in one shared-operator model.
const (
	AuthLoopback     AuthenticationMode = "loopback"
	AuthBearer       AuthenticationMode = "bearer"
	AuthTrustedProxy AuthenticationMode = "trusted_proxy"
)

// Authentication configures one stable operator identity source for every route.
type Authentication struct {
	Mode              AuthenticationMode
	Credentials       map[string]string
	TrustedProxyCIDRs []netip.Prefix
	IdentityHeader    string
	LocalOperatorID   string
}

func newAuthenticator(config Authentication) (func(*http.Request) (string, bool), error) {
	mode := config.Mode
	if mode == "" {
		mode = AuthLoopback
	}
	identityHeader := config.IdentityHeader
	if identityHeader == "" {
		identityHeader = defaultIdentityHeader
	}
	switch mode {
	case AuthLoopback:
		operatorID := config.LocalOperatorID
		if operatorID == "" {
			operatorID = "local-operator"
		}
		return func(request *http.Request) (string, bool) {
			if hasIdentityHeader(request, identityHeader) || !remoteIsLoopback(request) {
				return "", false
			}
			return operatorID, true
		}, nil
	case AuthBearer:
		credentials, err := validateCredentials(config.Credentials)
		if err != nil {
			return nil, err
		}
		return func(request *http.Request) (string, bool) {
			if hasIdentityHeader(request, identityHeader) {
				return "", false
			}
			return bearerOperator(request.Header.Get("Authorization"), credentials)
		}, nil
	case AuthTrustedProxy:
		if len(config.TrustedProxyCIDRs) == 0 {
			return nil, fmt.Errorf("trusted proxy mode requires at least one proxy CIDR")
		}
		for _, prefix := range config.TrustedProxyCIDRs {
			if !prefix.IsValid() {
				return nil, fmt.Errorf("trusted proxy CIDR is invalid")
			}
		}
		return func(request *http.Request) (string, bool) {
			address, ok := remoteAddress(request)
			if !ok || !containsAddress(config.TrustedProxyCIDRs, address) {
				return "", false
			}
			values := request.Header.Values(identityHeader)
			if len(values) != 1 {
				return "", false
			}
			operatorID := strings.TrimSpace(values[0])
			if operatorID == "" {
				return "", false
			}
			return operatorID, true
		}, nil
	default:
		return nil, fmt.Errorf("authentication mode %q is invalid", mode)
	}
}

func validateCredentials(credentials map[string]string) (map[string]string, error) {
	if len(credentials) == 0 {
		return nil, fmt.Errorf("bearer authentication requires at least one credential")
	}
	validated := make(map[string]string, len(credentials))
	for credential, operatorID := range credentials {
		if credential == "" || strings.TrimSpace(operatorID) == "" {
			return nil, fmt.Errorf("bearer credentials and operator IDs must be non-empty")
		}
		validated[credential] = strings.TrimSpace(operatorID)
	}
	return validated, nil
}

func bearerOperator(header string, credentials map[string]string) (string, bool) {
	credential, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || credential == "" || strings.ContainsAny(credential, "\r\n") {
		return "", false
	}
	var operatorID string
	matched := 0
	for candidate, mappedOperatorID := range credentials {
		if subtle.ConstantTimeCompare([]byte(credential), []byte(candidate)) == 1 {
			operatorID = mappedOperatorID
			matched = 1
		}
	}
	return operatorID, matched == 1
}

func remoteIsLoopback(request *http.Request) bool {
	address, ok := remoteAddress(request)
	return ok && address.IsLoopback()
}

func remoteAddress(request *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func containsAddress(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
