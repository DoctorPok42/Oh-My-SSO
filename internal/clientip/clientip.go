// Package clientip finds the IP address of the client behind a request.
//
// When browsers connect straight to the server, the client is the TCP peer
// (http.Request.RemoteAddr). Behind a reverse proxy (nginx, Traefik, a load
// balancer, Cloudflare...), the TCP peer is the proxy, and the proxy passes
// the client's address in a header: X-Forwarded-For, or a single-IP header
// such as X-Real-IP or CF-Connecting-IP.
//
// Anyone can send those headers. So they are read only when the TCP peer
// is one of the proxies listed in TRUSTED_PROXIES; any other request is
// attributed to its TCP peer, whatever headers it carries. Without this
// rule, a client could pick a new address on every request and walk
// around the per-IP rate limits, and fill the audit log, the sign-in
// history and the "new device / new country" signals with fake addresses.
//
// The header parsing itself is chi's (ClientIPFromXFF, ClientIPFromHeader,
// ClientIPFromRemoteAddr), which replace the deprecated middleware.RealIP:
// https://github.com/go-chi/chi/blob/v5.3.2/middleware/client_ip.go
package clientip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

const xForwardedFor = "X-Forwarded-For"

// Resolver decides which address a request comes from. The zero value
// trusts no proxy: the address is always the TCP peer.
type Resolver struct {
	trusted []netip.Prefix
	// header is the single-IP header to read from a trusted proxy;
	// "" means X-Forwarded-For.
	header string
}

// Parse builds a Resolver from the values of TRUSTED_PROXIES (IPs or
// CIDRs, comma separated, empty = no proxy) and CLIENT_IP_HEADER (empty =
// X-Forwarded-For).
func Parse(trustedProxies, header string) (Resolver, error) {
	var res Resolver
	for _, part := range strings.Split(trustedProxies, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := parsePrefix(part)
		if err != nil {
			return Resolver{}, fmt.Errorf("TRUSTED_PROXIES: %w", err)
		}
		res.trusted = append(res.trusted, p)
	}

	header = strings.TrimSpace(header)
	if header != "" {
		if len(res.trusted) == 0 {
			return Resolver{}, errors.New("CLIENT_IP_HEADER is set but TRUSTED_PROXIES is empty: the header would never be read")
		}
		if strings.EqualFold(header, xForwardedFor) {
			return Resolver{}, errors.New("CLIENT_IP_HEADER must name a single-IP header (X-Real-IP, CF-Connecting-IP...): leave it empty to use X-Forwarded-For")
		}
		res.header = http.CanonicalHeaderKey(header)
	}
	return res, nil
}

// parsePrefix accepts a CIDR ("10.0.0.0/8") or a single IP ("10.0.0.7",
// read as 10.0.0.7/32).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither an IP nor a CIDR", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// TrustsProxies reports whether at least one proxy is trusted.
func (res Resolver) TrustsProxies() bool { return len(res.trusted) > 0 }

// String describes the configuration, for the startup log.
func (res Resolver) String() string {
	if !res.TrustsProxies() {
		return "client ip: TCP peer address (TRUSTED_PROXIES is empty, X-Forwarded-For and similar headers are ignored)"
	}
	header := res.header
	if header == "" {
		header = xForwardedFor
	}
	return fmt.Sprintf("client ip: %s when the request comes from %s, TCP peer address otherwise",
		header, strings.Join(res.prefixStrings(), ","))
}

func (res Resolver) prefixStrings() []string {
	out := make([]string, len(res.trusted))
	for i, p := range res.trusted {
		out[i] = p.String()
	}
	return out
}

// Middleware stores the client address of each request; read it with
// FromRequest. Mount it before anything that reads the address.
func (res Resolver) Middleware(next http.Handler) http.Handler {
	direct := middleware.ClientIPFromRemoteAddr(next)
	if !res.TrustsProxies() {
		return direct
	}

	var viaProxy http.Handler
	if res.header != "" {
		viaProxy = middleware.ClientIPFromHeader(res.header)(next)
	} else {
		// Walks X-Forwarded-For from the right and skips the trusted
		// proxies: the first address that is not one of them is the client.
		viaProxy = middleware.ClientIPFromXFF(res.prefixStrings()...)(next)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if res.isTrustedPeer(r) {
			viaProxy.ServeHTTP(w, r)
			return
		}
		direct.ServeHTTP(w, r)
	})
}

// isTrustedPeer: the TCP connection comes from one of the trusted proxies.
func (res Resolver) isTrustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	peer = peer.Unmap().WithZone("")
	for _, p := range res.trusted {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// FromRequest returns the client address of r, as found by Middleware.
// When Middleware did not run (unit tests) or found no usable header (a
// trusted proxy that sent none, or garbage), it is the TCP peer: never an
// address taken from a header we cannot trust.
func FromRequest(r *http.Request) string {
	if ip := middleware.GetClientIP(r.Context()); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
