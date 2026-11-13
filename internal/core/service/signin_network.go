package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"sso.internal/sso/internal/core/repository"
)

// SignInNetworkService applies the IP allowlist of a realm (Settings >
// Security, ip_allowlist): when the list is not empty, a sign-in (password,
// passkey without password) is only possible from an address it contains.
// The refusal comes before any check, so an attempt from elsewhere does not
// count towards the lockout of the account: in the master realm, nobody
// outside the list can lock an administrator out (audit B-14).
//
// Only sign-in is filtered. A session already open keeps working, and the
// applications' servers (token, userinfo, metadata, JWKS) are never filtered:
// they do not call from the users' network.
type SignInNetworkService struct {
	settings *settingsCache
}

// NewSignInNetworkService: settings nil means no realm has a list.
func NewSignInNetworkService(settings repository.InstanceSettingsRepository, logger *slog.Logger) *SignInNetworkService {
	return &SignInNetworkService{settings: newSettingsCache(settings, logger)}
}

// Allows tells whether ip may sign in to the realm: always when its list is
// empty. It fails closed: when the settings cannot be read, it returns the
// error (and false). Changes apply within a minute (settings cache).
func (s *SignInNetworkService) Allows(ctx context.Context, realmID, ip string) (bool, error) {
	st, err := s.settings.getStrict(ctx, realmID)
	if err != nil {
		return false, fmt.Errorf("sign-in network: settings: %w", err)
	}
	return IPAllowed(st.IPAllowlist, ip), nil
}

// IPAllowed tells whether ip is in list (IP addresses and CIDR ranges, as
// the Admin API stores them). An empty list allows every address. An address
// that cannot be read is in no list; an entry that cannot be read matches
// nothing (the list stays closed rather than open).
func IPAllowed(list []string, ip string) bool {
	empty := true
	for _, entry := range list {
		if strings.TrimSpace(entry) != "" {
			empty = false
			break
		}
	}
	if empty {
		return true
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, entry := range list {
		if p, ok := parseAllowEntry(entry); ok && p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseAllowEntry reads "192.0.2.7", "10.0.0.0/8" or "2001:db8::/32" as a
// prefix (a single address is a /32 or /128). Like net.ParseCIDR, which the
// Admin API validates with, "10.1.2.3/8" is the network 10.0.0.0/8.
// IPv4-mapped IPv6 entries (::ffff:10.0.0.0/104) are read as IPv4, as the
// client's address is.
func parseAllowEntry(entry string) (netip.Prefix, bool) {
	entry = strings.TrimSpace(entry)
	if !strings.Contains(entry, "/") {
		addr, err := netip.ParseAddr(entry)
		if err != nil || addr.Zone() != "" {
			return netip.Prefix{}, false
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	p, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, false
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false // wider than the whole IPv4 space: not an IPv4 range
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}
