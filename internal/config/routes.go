package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// UpstreamEntry holds the validated base URL for an upstream service.
type UpstreamEntry struct {
	BaseURL string
}

// RouteTable is an allowlist mapping service name to upstream entry.
// Only service names present in this map are proxied; all others get 404.
type RouteTable map[string]UpstreamEntry

// ParseRouteTable builds the route table from config.
// It always includes "user" from UserUpstreamURL and optionally additional
// services from the comma-separated GATEWAY_UPSTREAMS value.
func ParseRouteTable(cfg *Config) (RouteTable, error) {
	table := make(RouteTable)
	isProd := strings.EqualFold(cfg.Env, "production")

	// The "user" service is always required.
	if err := addEntryWithEnv(table, "user", cfg.UserUpstreamURL, isProd); err != nil {
		return nil, fmt.Errorf("user upstream: %w", err)
	}

	// Parse additional upstreams from GATEWAY_UPSTREAMS (comma-separated svc=url).
	if cfg.Upstreams != "" {
		pairs := strings.Split(cfg.Upstreams, ",")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid upstream entry %q: expected svc=url format", pair)
			}

			svc := strings.TrimSpace(parts[0])
			rawURL := strings.TrimSpace(parts[1])

			if svc == "" {
				return nil, fmt.Errorf("upstream entry has empty service name: %q", pair)
			}

			if err := addEntryWithEnv(table, svc, rawURL, isProd); err != nil {
				return nil, fmt.Errorf("upstream %q: %w", svc, err)
			}
		}
	}

	return table, nil
}

// forbiddenRanges lists IP prefixes that must never be used as upstream targets.
// Link-local (169.254.0.0/16, fe80::/10) and cloud-metadata (169.254.169.254/32)
// are blocked in ALL environments. Loopback (127.0.0.0/8, ::1/128) is blocked in
// production only (allowed in development so local integration tests can run).
var (
	// Always-forbidden ranges (link-local / cloud metadata).
	alwaysForbidden = []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"), // IPv4 link-local incl. 169.254.169.254
		netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
	}

	// Loopback ranges — forbidden in production, allowed in development.
	loopbackRanges = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
)

// checkSSRF returns an error if the upstream URL host is an IP literal that falls
// into a forbidden range. Hostnames are always allowed (internal services legitimately
// live on private RFC-1918 ranges that are accessed via DNS).
// isProduction should be true when GATEWAY_ENV == "production".
func checkSSRF(parsedURL *url.URL, isProduction bool) error {
	// Extract the host without port.
	host := parsedURL.Hostname()

	addr, parseErr := netip.ParseAddr(host)
	if parseErr != nil {
		// Not an IP literal (parse error means it is a hostname) — allow it.
		// SSRF guard only applies to IP literals; hostnames resolve via DNS at runtime.
		return nil //nolint:nilerr // intentional: ParseAddr error = not an IP literal, not an SSRF risk
	}

	// Canonicalize IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) to plain IPv4 so the
	// IPv4 prefix checks below actually match it — without Unmap the mapped form is a
	// different address family and slips past the link-local/loopback guards (NEW-M1).
	addr = addr.Unmap()

	// Check always-forbidden ranges.
	for _, prefix := range alwaysForbidden {
		if prefix.Contains(addr) {
			return fmt.Errorf("upstream host %q is in forbidden range %s (link-local/metadata)", host, prefix)
		}
	}

	// In production, loopback is also forbidden.
	if isProduction {
		for _, prefix := range loopbackRanges {
			if prefix.Contains(addr) {
				return fmt.Errorf("upstream host %q is in forbidden loopback range %s (not allowed in production)", host, prefix)
			}
		}
	}

	return nil
}

// addEntryWithEnv validates and adds a service->URL mapping to the table.
// isProduction controls whether loopback addresses are also blocked.
func addEntryWithEnv(table RouteTable, svc, rawURL string, isProduction bool) error {
	if rawURL == "" {
		return fmt.Errorf("URL is empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse URL %q: %w", rawURL, err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("URL %q has unsupported scheme %q (only http/https allowed)", rawURL, parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("URL %q has empty host", rawURL)
	}

	// SSRF guard: reject link-local / metadata IP literals and loopback in production.
	if err := checkSSRF(parsed, isProduction); err != nil {
		return err
	}

	// Normalise: strip trailing slash from base URL.
	base := strings.TrimRight(rawURL, "/")
	table[svc] = UpstreamEntry{BaseURL: base}

	return nil
}
