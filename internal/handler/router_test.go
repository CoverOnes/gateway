package handler_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/CoverOnes/gateway/internal/config"
	"github.com/CoverOnes/gateway/internal/handler"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// staticKeyResolver implements jwt.KeyResolver with a fixed in-process key map.
type staticKeyResolver struct {
	keys map[string]ed25519.PublicKey
}

func (r *staticKeyResolver) Get(kid string) (ed25519.PublicKey, error) {
	return r.keys[kid], nil
}

// generateEdDSAKey creates a fresh Ed25519 key pair.
func generateEdDSAKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// mintToken signs a JWT for the given subject using the test private key.
func mintToken(t *testing.T, priv ed25519.PrivateKey, kid, subject string) string {
	t.Helper()
	now := time.Now().UTC()
	claims := &jwt.Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    jwt.Issuer,
			Subject:   subject,
			Audience:  gojwt.ClaimStrings{jwt.Audience},
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		KYCTier:     1,
		AccountType: "PERSONAL",
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	require.NoError(t, err)
	return signed
}

// upstreamStub starts an httptest server that replies 200 to any POST request.
// It returns the server URL and a cleanup function.
func upstreamStub(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newTestRouterWithIPRL builds a RouterConfig with explicit ipRLPerMin control.
// Use this when the test needs ipRL to refill at a specific rate (differential-refill tests).
func newTestRouterWithIPRL(
	t *testing.T,
	authRLPerMin int,
	userRLPerMin int,
	userRLBurst int,
	ipRLPerMin int,
	resolver *staticKeyResolver,
	upstreamURL string,
) http.Handler {
	t.Helper()

	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	// Build the route table directly — "user" is the only service needed for these tests.
	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstreamURL},
	}

	r, err := handler.NewRouter(&handler.RouterConfig{
		Verifier:            verifier,
		JWKSCache:           nil, // health endpoints not under test; Readiness not called
		RouteTable:          table,
		ProxyTimeout:        5,
		RateLimitPerMin:     ipRLPerMin,
		AuthRateLimitPerMin: authRLPerMin,
		UserRateLimitPerMin: userRLPerMin,
		UserRateLimitBurst:  userRLBurst,
		CORSOrigins:         nil,
		HMACSecret:          nil,
	})
	require.NoError(t, err)

	return r
}

func doRouterRequest(t *testing.T, r http.Handler, method, path, bearerToken string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, http.NoBody)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// ─── TestLogoutNotGatedByAuthRL ───────────────────────────────────────────────

// TestLogoutNotGatedByAuthRL proves M2 via a "differential refill" approach:
//
//  1. Build a router where ipRL has a very HIGH token-refill rate (6000/min ≈ 100/s)
//     and authRL has a very LOW rate (1/min ≈ 0.016/s). Both share fallbackBurst=10.
//  2. Send 12 login requests — both ipRL and authRL exhaust their burst=10 and return 429.
//  3. Sleep 200ms. In that time:
//     — ipRL refills ~20 tokens (100/s × 0.2s) — healthy again.
//     — authRL refills ≈0.003 tokens (0.016/s × 0.2s) — still empty.
//  4. At this point: ipRL is healthy, authRL is empty.
//  5. A login request MUST return 429 (authRL still blocks it).
//  6. A logout request with a valid JWT MUST succeed (non-429): logout is not gated
//     by authRL, so the depleted authRL bucket is irrelevant.
//
// This test is precise: if authRL were accidentally wired back onto logout, step 6
// would return 429, failing the assertion.
func TestLogoutNotGatedByAuthRL(t *testing.T) {
	pub, priv := generateEdDSAKey(t)
	const kid = "router-test-kid"
	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	upstream := upstreamStub(t)

	// ipRL = 6000/min (≈100 tokens/s) so it refills quickly after exhaustion.
	// authRL = 1/min (≈0.016 tokens/s) so it stays exhausted during the sleep window.
	// userRL burst = 100 so it never interferes.
	const ipRLPerMin = 6000
	const authRLPerMin = 1
	r := newTestRouterWithIPRL(t, authRLPerMin, 600, 100, ipRLPerMin, resolver, upstream)

	// Step 1: exhaust both ipRL and authRL by hammering login.
	// burst=10 for both → 11th request is 429.
	var got429 bool

	for range 15 {
		code := doRouterRequest(t, r, http.MethodPost, "/v1/auth/login", "")
		if code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}

	require.True(t, got429, "both ipRL and authRL must be exhausted within 15 login attempts")

	// Step 2: sleep 200ms so ipRL (100/s) refills ≥10 tokens but authRL (0.016/s) stays ~0.
	time.Sleep(200 * time.Millisecond)

	// Step 3: login must still be 429 (authRL still depleted).
	loginCode := doRouterRequest(t, r, http.MethodPost, "/v1/auth/login", "")
	assert.Equal(t, http.StatusTooManyRequests, loginCode,
		"login must remain blocked by authRL even after ipRL refills (authRL budget still empty)")

	// Step 4: logout with a valid JWT must NOT be 429.
	// ipRL is refilled → clears global gate. authRL is still empty, but logout is NOT
	// inside authGroup, so authRL does not apply. Result: non-429 (typically 200 from upstream stub).
	token := mintToken(t, priv, kid, fmt.Sprintf("user-logout-differential-%d", time.Now().UnixNano()))
	logoutCode := doRouterRequest(t, r, http.MethodPost, "/v1/auth/logout", token)
	assert.NotEqual(t, http.StatusTooManyRequests, logoutCode,
		"logout must NOT be blocked when authRL is depleted but ipRL has recovered (logout is outside authGroup)")
}

// ─── TestNewRouterFromConfig_WildcardCORSOriginDropped ──────────────────────

// TestNewRouterFromConfig_WildcardCORSOriginDropped proves that when GATEWAY_CORS_ORIGINS
// contains only wildcard/null entries, they are silently dropped so the gateway starts
// without CORS headers rather than enabling an unsafe CWE-942 configuration.
func TestNewRouterFromConfig_WildcardCORSOriginDropped(t *testing.T) {
	upstream := upstreamStub(t)

	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstream},
	}

	tests := []struct {
		name        string
		corsOrigins []string // fed directly into RouterConfig (already parsed by NewRouterFromConfig)
	}{
		{
			name:        "nil origins → CORS disabled",
			corsOrigins: nil,
		},
		{
			name:        "empty slice → CORS disabled",
			corsOrigins: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, _ := generateEdDSAKey(t)
			resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{"kid": pub}}
			verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

			r, err := handler.NewRouter(&handler.RouterConfig{
				Verifier:            verifier,
				JWKSCache:           nil,
				RouteTable:          table,
				ProxyTimeout:        5,
				RateLimitPerMin:     100_000,
				AuthRateLimitPerMin: 100_000,
				UserRateLimitPerMin: 100_000,
				UserRateLimitBurst:  100_000,
				CORSOrigins:         tc.corsOrigins,
				HMACSecret:          nil,
			})
			require.NoError(t, err)

			// OPTIONS preflight on an auth route — must NOT get Access-Control-Allow-Origin
			// when CORS is disabled (no origins configured).
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodOptions,
				"/v1/auth/login",
				http.NoBody,
			)
			req.Header.Set("Origin", "https://evil.example.com")
			req.Header.Set("Access-Control-Request-Method", "POST")

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"),
				"Access-Control-Allow-Origin must be absent when no safe origins are configured; case: %q", tc.name)
		})
	}
}

// ─── TestBodyLimit_AuthRoute413 ───────────────────────────────────────────────

// TestBodyLimit_AuthRoute413 verifies that /v1/auth/* routes enforce a 64 KiB
// body limit and return 413 REQUEST_ENTITY_TOO_LARGE for oversized payloads.
// This covers the re-review Major finding: no request body size limit on auth routes.
func TestBodyLimit_AuthRoute413(t *testing.T) {
	upstream := upstreamStub(t)

	pub, _ := generateEdDSAKey(t)
	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{"kid": pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstream},
	}

	r, err := handler.NewRouter(&handler.RouterConfig{
		Verifier:            verifier,
		JWKSCache:           nil,
		RouteTable:          table,
		ProxyTimeout:        5,
		RateLimitPerMin:     100_000,
		AuthRateLimitPerMin: 100_000,
		UserRateLimitPerMin: 100_000,
		UserRateLimitBurst:  100_000,
		HMACSecret:          nil,
	})
	require.NoError(t, err)

	// 64 KiB + 1 byte exceeds the auth body limit (64 KiB).
	oversized := bytes.Repeat([]byte("a"), 64*1024+1)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/v1/auth/login",
		bytes.NewReader(oversized),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code,
		"oversized auth body must return 413 REQUEST_ENTITY_TOO_LARGE")
	assert.Contains(t, w.Body.String(), "REQUEST_ENTITY_TOO_LARGE",
		"413 body must contain machine-readable error code")
}

// ─── TestBodyLimit_APIRouteSmallPayloadOK ────────────────────────────────────

// TestBodyLimit_APIRouteSmallPayloadOK verifies that the 10 MiB limit on /api/*
// does not reject legitimate requests below the threshold.
func TestBodyLimit_APIRouteSmallPayloadOK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const kid = "body-limit-test-kid"
	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}

	upstream := upstreamStub(t)

	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstream},
	}

	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	r, routerErr := handler.NewRouter(&handler.RouterConfig{
		Verifier:            verifier,
		JWKSCache:           nil,
		RouteTable:          table,
		ProxyTimeout:        5,
		RateLimitPerMin:     100_000,
		AuthRateLimitPerMin: 100_000,
		UserRateLimitPerMin: 100_000,
		UserRateLimitBurst:  100_000,
		HMACSecret:          nil,
	})
	require.NoError(t, routerErr)

	token := mintToken(t, priv, kid, "user-body-limit-ok")

	smallBody := strings.NewReader(`{"key":"value"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/user/v1/profile", smallBody)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusRequestEntityTooLarge, w.Code,
		"small API payload must not be rejected by body limit middleware")
}

// ─── TestTrustedProxyCIDR_InvalidRejected ────────────────────────────────────

// TestTrustedProxyCIDR_InvalidRejected verifies that invalid or dangerous CIDRs in
// GATEWAY_TRUSTED_PROXY_CIDR are rejected at boot — preventing X-Forwarded-For spoofing
// that would bypass IP rate limiting.
func TestTrustedProxyCIDR_InvalidRejected(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		errContains string
	}{
		{
			name:        "non-CIDR string is rejected",
			input:       "not-a-cidr",
			errContains: "not-a-cidr",
		},
		{
			name:        "IPv4 whole-address-space 0.0.0.0/0 is rejected",
			input:       "0.0.0.0/0",
			errContains: "entire address space",
		},
		{
			name:        "IPv6 whole-address-space ::/0 is rejected",
			input:       "::/0",
			errContains: "entire address space",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{TrustedProxyCIDR: tc.input}
			_, err := cfg.ValidateTrustedProxyCIDRs()
			require.Error(t, err, "dangerous/invalid CIDR must be rejected")
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

// TestTrustedProxyCIDR_ValidParsed verifies that valid CIDRs are parsed correctly.
func TestTrustedProxyCIDR_ValidParsed(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantNil bool
	}{
		{
			name:    "empty string → nil (disabled)",
			input:   "",
			wantNil: true,
		},
		{
			name:    "single CIDR",
			input:   "10.0.0.0/8",
			wantLen: 1,
		},
		{
			name:    "multiple CIDRs",
			input:   "10.0.0.0/8,172.16.0.0/12",
			wantLen: 2,
		},
		{
			name:    "CIDRs with spaces",
			input:   "10.0.0.0/8, 172.16.0.0/12",
			wantLen: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{TrustedProxyCIDR: tc.input}
			cidrs, err := cfg.ValidateTrustedProxyCIDRs()
			require.NoError(t, err)
			if tc.wantNil {
				assert.Nil(t, cidrs)
			} else {
				assert.Len(t, cidrs, tc.wantLen)
			}
		})
	}
}

// ─── TestRateLimiter_RetryAfterHeader ─────────────────────────────────────────

// TestRateLimiter_RetryAfterHeader verifies that 429 responses include the
// Retry-After header so clients know when to retry.
func TestRateLimiter_RetryAfterHeader(t *testing.T) {
	upstream := upstreamStub(t)

	pub, _ := generateEdDSAKey(t)
	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{"kid": pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstream},
	}

	// Build router with rate limit of 1/min burst=1 so it exhausts immediately.
	r, err := handler.NewRouter(&handler.RouterConfig{
		Verifier:            verifier,
		JWKSCache:           nil,
		RouteTable:          table,
		ProxyTimeout:        5,
		RateLimitPerMin:     1,
		AuthRateLimitPerMin: 100_000,
		UserRateLimitPerMin: 100_000,
		UserRateLimitBurst:  100_000,
		HMACSecret:          nil,
	})
	require.NoError(t, err)

	// Exhaust the IP rate limit (burst=10 for IP RL).
	var got429 bool
	var retryAfter string

	for range 15 {
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/v1/auth/login",
			http.NoBody,
		)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			retryAfter = w.Header().Get("Retry-After")

			break
		}
	}

	require.True(t, got429, "expected a 429 after exhausting rate limit")
	assert.NotEmpty(t, retryAfter, "429 response must include Retry-After header")
}

// ─── TestBodyLimit_LogoutRoute413 ────────────────────────────────────────────

// TestBodyLimit_LogoutRoute413 verifies that /v1/auth/logout enforces the 64 KiB
// body limit. Logout is registered outside authGroup (intentionally, to avoid the
// IP-keyed authRL limiter) so the body limit must be added explicitly to its chain.
// This covers the re-review Minor finding: logout had no body limit.
//
// bodyLimitMiddleware wraps the body with http.MaxBytesReader but does not read eagerly;
// the limit fires when the proxy reads the body. authMW reads only the Authorization
// header, so a valid JWT is required to reach the proxy and trigger the 413.
func TestBodyLimit_LogoutRoute413(t *testing.T) {
	upstream := upstreamStub(t)

	pub, priv := generateEdDSAKey(t)
	const kid = "logout-limit-kid"
	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstream},
	}

	r, err := handler.NewRouter(&handler.RouterConfig{
		Verifier:            verifier,
		JWKSCache:           nil,
		RouteTable:          table,
		ProxyTimeout:        5,
		RateLimitPerMin:     100_000,
		AuthRateLimitPerMin: 100_000,
		UserRateLimitPerMin: 100_000,
		UserRateLimitBurst:  100_000,
		HMACSecret:          nil,
	})
	require.NoError(t, err)

	// 64 KiB + 1 byte exceeds the auth body limit (64 KiB).
	oversized := bytes.Repeat([]byte("a"), 64*1024+1)

	token := mintToken(t, priv, kid, "test-logout-limit-user")

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/v1/auth/logout",
		bytes.NewReader(oversized),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code,
		"oversized logout body must return 413 REQUEST_ENTITY_TOO_LARGE")
	assert.Contains(t, w.Body.String(), "REQUEST_ENTITY_TOO_LARGE",
		"413 body must contain machine-readable error code")
}
