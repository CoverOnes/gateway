// Package jwks provides a JWKS cache that fetches and refreshes Ed25519 public keys
// from the user service /jwks endpoint.
package jwks

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	authjwt "github.com/CoverOnes/gateway/internal/auth/jwt"
)

// Cache holds an in-memory map of kid->ed25519.PublicKey with TTL-based refresh.
// It is safe for concurrent use. Fetch failures keep the last-good key set (fail-secure).
type Cache struct {
	mu        sync.RWMutex
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time

	// inflightMu + inflightCond guard the single-flight fetch.
	// Waiters sleep on inflightCond.Wait() instead of spinning with time.Sleep.
	inflightMu   sync.Mutex
	inflightCond *sync.Cond
	inflight     bool

	jwksURL string
	ttl     time.Duration
	client  *http.Client
}

// noRedirectAcrossHosts is a CheckRedirect function that allows redirects within the
// same host (scheme+host) but rejects any redirect that changes the target host.
// This prevents a compromised or misconfigured JWKS endpoint from redirecting the
// gateway to a cloud-metadata service or other SSRF-forbidden destination.
func noRedirectAcrossHosts(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}

	original, err := url.Parse(via[0].URL.String())
	if err != nil {
		return fmt.Errorf("jwks redirect rejected: cannot parse original URL: %w", err)
	}

	if req.URL.Host != original.Host {
		return fmt.Errorf("jwks redirect rejected: cross-host redirect from %q to %q is not allowed",
			original.Host, req.URL.Host)
	}

	return nil
}

// NewCache creates a JWKS cache and performs the initial fetch.
// A warning is emitted for transient fetch failures; the gateway will start with an
// empty cache and report not_ready until a successful fetch.
//
// The underlying HTTP client rejects cross-host redirects to prevent SSRF via a
// compromised/misconfigured JWKS endpoint that issues a 302 to a metadata service.
func NewCache(jwksURL string, ttl, fetchTimeout time.Duration) *Cache {
	c := &Cache{
		keys:    make(map[string]ed25519.PublicKey),
		jwksURL: jwksURL,
		ttl:     ttl,
		client: &http.Client{
			Timeout:       fetchTimeout,
			CheckRedirect: noRedirectAcrossHosts,
		},
	}
	c.inflightCond = sync.NewCond(&c.inflightMu)

	return c
}

// Start performs the initial JWKS fetch and launches a background refresh goroutine.
// ctx governs the background goroutine; cancel it to stop the refresher.
func (c *Cache) Start(ctx context.Context) {
	if err := c.fetch(); err != nil {
		slog.Warn("initial JWKS fetch failed; /readyz will report not_ready until fetch succeeds", "err", err)
	}

	go c.refreshLoop(ctx)
}

// Get returns the ed25519.PublicKey for the given kid.
// On a cache miss, it triggers a single-flight synchronous re-fetch (absorbs key rotation).
// Returns nil if the kid is not found even after re-fetch.
func (c *Cache) Get(kid string) (ed25519.PublicKey, error) {
	c.mu.RLock()
	pub, ok := c.keys[kid]
	c.mu.RUnlock()

	if ok {
		return pub, nil
	}

	// Cache miss: try single-flight refresh. The hasKid callback lets a woken
	// waiter reuse a key that the leader just fetched, skipping a redundant GET.
	hasKid := func() bool {
		c.mu.RLock()
		_, found := c.keys[kid]
		c.mu.RUnlock()

		return found
	}

	if err := c.singleFlightFetch(hasKid); err != nil {
		slog.Warn("JWKS refresh on unknown kid failed", "kid", kid, "err", err)
		// Keep last-good keys; return nil for this kid (will become 401 UNAUTHORIZED).
	}

	c.mu.RLock()
	pub, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, nil
	}

	return pub, nil
}

// Ready reports whether the cache has at least one key loaded.
// Used by /readyz to determine gateway readiness.
func (c *Cache) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.keys) > 0
}

// singleFlightFetch prevents stampedes of concurrent refreshes on unknown-kid.
// Only one goroutine performs the fetch at a time; others block on a sync.Cond
// (no spin-wait) until the in-flight fetch completes.
//
// satisfied is an optional cache re-check: when a waiter is woken after the
// leader's fetch completes, it calls satisfied() and — if the leader already
// populated the key it needed — returns immediately WITHOUT issuing its own
// fetch. This guarantees that N concurrent unknown-kid lookups collapse into a
// single upstream GET (the leader's), instead of N back-to-back fetches.
// A nil satisfied callback always fetches (used by callers that just want a
// fresh refresh regardless of any specific kid).
func (c *Cache) singleFlightFetch(satisfied func() bool) error {
	c.inflightMu.Lock()

	// woken is true once we have slept on the condition at least once, meaning
	// some other goroutine's fetch completed between our entry and our wake.
	woken := false
	for c.inflight {
		c.inflightCond.Wait() // releases inflightMu; re-acquires on wake
		woken = true
	}

	// We were woken by the leader's Broadcast and a previous fetch already ran.
	// If that fetch satisfied our need, reuse it and skip our own GET.
	if woken && satisfied != nil && satisfied() {
		c.inflightMu.Unlock()

		return nil
	}

	// We now hold inflightMu and inflight == false; become the leader.
	c.inflight = true
	c.inflightMu.Unlock()

	defer func() {
		c.inflightMu.Lock()
		c.inflight = false
		c.inflightCond.Broadcast() // wake all waiters
		c.inflightMu.Unlock()
	}()

	return c.fetch()
}

// fetch GETs the JWKS URL and atomically updates the cache.
// On error, the existing key set is preserved (fail-secure).
func (c *Cache) fetch() error {
	resp, err := c.client.Get(c.jwksURL) //nolint:noctx // JWKS client uses its own Timeout; no per-request context needed
	if err != nil {
		return fmt.Errorf("GET %s: %w", c.jwksURL, err)
	}

	defer resp.Body.Close() //nolint:errcheck // best-effort close on JWKS response

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	// Limit body to 1 MiB to prevent OOM if the upstream returns a huge response.
	limited := io.LimitReader(resp.Body, 1<<20)

	var jwksResp authjwt.JWKS
	if err := json.NewDecoder(limited).Decode(&jwksResp); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	newKeys := make(map[string]ed25519.PublicKey, len(jwksResp.Keys))

	for i := range jwksResp.Keys {
		key := &jwksResp.Keys[i]

		pub, parseErr := authjwt.ParsePublicKey(key)
		if parseErr != nil {
			slog.Warn("JWKS: skipping unparseable key", "kid", key.Kid, "err", parseErr)

			continue
		}

		newKeys[key.Kid] = pub
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("JWKS response contained no valid Ed25519 keys")
	}

	// Atomic swap.
	c.mu.Lock()
	c.keys = newKeys
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	slog.Info("JWKS cache refreshed", "key_count", len(newKeys))

	return nil
}

// refreshLoop periodically refreshes the JWKS cache until ctx is canceled.
func (c *Cache) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.fetch(); err != nil {
				slog.Warn("JWKS background refresh failed; retaining last-good keys", "err", err)
			}
		}
	}
}
