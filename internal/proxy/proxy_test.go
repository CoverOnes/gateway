package proxy_test

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CoverOnes/gateway/internal/auth/jwks"
	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/CoverOnes/gateway/internal/config"
	"github.com/CoverOnes/gateway/internal/handler"
	"github.com/CoverOnes/gateway/internal/platform/health"
	"github.com/CoverOnes/gateway/internal/proxy"
)

// upstreamCapturer is a test upstream that records what it receives.
type upstreamCapturer struct {
	receivedHeaders http.Header
	receivedPath    string
	responseStatus  int
	responseBody    string
}

func (u *upstreamCapturer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.receivedHeaders = r.Header.Clone()
	u.receivedPath = r.URL.Path

	status := u.responseStatus
	if status == 0 {
		status = http.StatusOK
	}

	w.WriteHeader(status)

	if u.responseBody != "" {
		_, _ = w.Write([]byte(u.responseBody))
	}
}

func generateEdDSAKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x := base64.RawURLEncoding.EncodeToString(pub)
	kid := "proxy-test-" + x[:8]

	return pub, priv, kid
}

func signTestToken(t *testing.T, priv ed25519.PrivateKey, kid, sub string) string {
	t.Helper()

	now := time.Now().UTC()
	claims := &jwt.Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    jwt.Issuer,
			Subject:   sub,
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

func buildRouter(t *testing.T, pub ed25519.PublicKey, kid, upstreamURL string) *handler.RouterConfig {
	t.Helper()

	return buildRouterWithHMAC(t, pub, kid, upstreamURL, nil)
}

// buildRouterWithHMAC mirrors buildRouter but also configures the gateway-origin
// HMAC signing secret. A nil secret disables signing (development parity).
// Used by TestProxy_HMACSignatureNotPathBound to exercise the signing path.
func buildRouterWithHMAC(t *testing.T, pub ed25519.PublicKey, kid, upstreamURL string, hmacSecret []byte) *handler.RouterConfig {
	t.Helper()

	x := base64.RawURLEncoding.EncodeToString(pub)

	// Serve a test JWKS.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"` + kid + `","x":"` + x + `"}]}`))
	}))
	t.Cleanup(jwksServer.Close)

	cache := jwks.NewCache(jwksServer.URL, 5*time.Minute, 5*time.Second)
	cache.Start(t.Context())

	verifier := jwt.NewVerifier(cache, "coverones-user", "coverones", 60)

	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstreamURL},
	}

	return &handler.RouterConfig{
		Verifier:            verifier,
		JWKSCache:           cache,
		RouteTable:          table,
		ProxyTimeout:        5,
		RateLimitPerMin:     100_000, // high limit so test suite never hits rate-limit 429
		AuthRateLimitPerMin: 100_000,
		UserRateLimitPerMin: 100_000,
		UserRateLimitBurst:  100_000,
		HMACSecret:          hmacSecret,
	}
}

func TestProxy_AllowlistedServiceProxiedToUpstream(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "user-abc")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/v1/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "allowlisted svc should proxy successfully")
	assert.Equal(t, "/v1/me", capturer.receivedPath, "prefix /api/user should be stripped")
}

func TestProxy_UnknownServiceReturns404(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "user-abc")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/unknown-svc/v1/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "unknown svc should return 404 SERVICE_NOT_FOUND")
	assert.Contains(t, w.Body.String(), "SERVICE_NOT_FOUND")
}

func TestProxy_InboundSpoofedIdentityHeaderIsStripped(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "real-sub")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/v1/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-User-Id", "spoofed-user-id") // attacker tries to spoof

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "real-sub", capturer.receivedHeaders.Get("X-User-Id"),
		"upstream must receive the real sub, not the spoofed value")
	assert.NotEqual(t, "spoofed-user-id", capturer.receivedHeaders.Get("X-User-Id"))
}

func TestProxy_Upstream5xxSurfacesGeneric502(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	// Upstream closes the connection immediately — this triggers a transport error
	// (not a normal 5xx) so the proxy's ErrorHandler fires and returns 502 BAD_GATEWAY
	// with a generic envelope (no internal details leaked to the client).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection and close it abruptly to force a transport error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			// Fallback: return 500 (will still be proxied through; this path is a test-env safety net).
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"internal":"secret db connection string"}`))

			return
		}

		conn, _, _ := hj.Hijack()
		_ = conn.Close() // best-effort close; abrupt disconnect triggers transport error in ReverseProxy
	}))
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "user-abc")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/v1/broken", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Transport error: proxy ErrorHandler MUST return 502 BAD_GATEWAY.
	assert.Equal(t, http.StatusBadGateway, w.Code, "transport error must surface as 502 BAD_GATEWAY")

	body := w.Body.String()
	// Generic envelope: must contain BAD_GATEWAY code.
	assert.Contains(t, body, "BAD_GATEWAY", "response must contain the generic error code")
	// Must NOT echo any upstream internals.
	assert.NotContains(t, body, "secret", "upstream internal details must not reach the client")
	assert.NotContains(t, body, "db connection", "upstream internal details must not reach the client")
}

func TestProxy_PublicRoutesDoNotRequireAuth(t *testing.T) {
	pub, _, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	// POST /v1/auth/register should work WITHOUT Authorization header.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/register", http.NoBody)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should proxy to upstream, not reject with 401.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code,
		"public register route should not require auth")
}

// TestProxy_SpoofedIdentityHeaderStrippedOnPublicRoute verifies G-M3: even on a
// public route (no Auth middleware), a client-supplied X-User-Id is stripped by the
// global StripIdentityHeaders middleware before reaching the upstream.
func TestProxy_SpoofedIdentityHeaderStrippedOnPublicRoute(t *testing.T) {
	pub, _, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	// Client sends spoofed identity header on public login route (no auth token).
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/login", http.NoBody)
	req.Header.Set("X-User-Id", "spoofed-admin-id")
	req.Header.Set("X-Kyc-Tier", "99")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Route should be reachable (not 401) but the spoofed headers must be stripped.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code,
		"public route must not require auth")
	assert.Empty(t, capturer.receivedHeaders.Get("X-User-Id"),
		"X-User-Id must be stripped on public routes by StripIdentityHeaders")
	assert.Empty(t, capturer.receivedHeaders.Get("X-Kyc-Tier"),
		"X-Kyc-Tier must be stripped on public routes by StripIdentityHeaders")
}

func TestProxy_HealthzNeverRequiresAuth(t *testing.T) {
	pub, _, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", http.NoBody)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

// TestProxy_ReadyzReflectsJWKSCacheState tests that /readyz returns 200 when JWKS is loaded.
func TestProxy_ReadyzReflectsJWKSCacheState(t *testing.T) {
	pub, _, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)

	h := health.NewHandler(routerCfg.JWKSCache)
	_ = h

	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Cache was populated in buildRouter, so /readyz should be 200.
	assert.Equal(t, http.StatusOK, w.Code)
}

// ─── Deny-by-default auth tests (Critical finding) ────────────────────────────
//
// These tests prove that the auth middleware wiring at router.go:154
// (api.Use(authMW)) actually turns a bad/missing token into a 401 and that the
// upstream is never reached. Without these tests an accidental deletion of
// api.Use(authMW) would ship green.

// TestProxy_ProtectedRoute_DeniesInvalidAuth is a table-driven test asserting that
// every /api/:svc/* request with an invalid or missing token gets:
//   - HTTP 401
//   - body containing "UNAUTHORIZED"
//   - upstream NOT reached
func TestProxy_ProtectedRoute_DeniesInvalidAuth(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	now := time.Now().UTC()

	// Build a token signed with a different key (tampered signature from the router's perspective).
	_, differentPriv, differentKid := generateEdDSAKey(t)
	wrongKeyToken := signTestToken(t, differentPriv, differentKid, "user-abc")

	// Build an expired token.
	expiredToken := mintToken(t, priv, kid, now.Add(-20*time.Minute), now.Add(-10*time.Minute))

	// Build a wrong-issuer token.
	wrongIssuerToken := mintTokenWithIssuer(t, priv, kid, "evil-issuer", now)

	// Build a tampered token: take a valid token and corrupt its signature segment.
	validToken := signTestToken(t, priv, kid, "user-abc")
	tamperedToken := tamperSignature(validToken)

	tests := []struct {
		name          string
		authorization string // full Authorization header value, or "" for no header
	}{
		{
			name:          "no Authorization header → 401",
			authorization: "",
		},
		{
			name:          "wrong scheme (Basic) → 401",
			authorization: "Basic dXNlcjpwYXNz",
		},
		{
			name:          "empty Bearer value → 401",
			authorization: "Bearer ",
		},
		{
			name:          "expired token → 401",
			authorization: "Bearer " + expiredToken,
		},
		{
			name:          "wrong issuer → 401",
			authorization: "Bearer " + wrongIssuerToken,
		},
		{
			name:          "tampered signature → 401",
			authorization: "Bearer " + tamperedToken,
		},
		{
			name:          "unknown kid → 401",
			authorization: "Bearer " + wrongKeyToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset capturer between sub-tests.
			capturer.receivedPath = ""
			capturer.receivedHeaders = nil

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/v1/me", http.NoBody)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"protected route must return 401 for %q", tc.name)
			assert.Contains(t, w.Body.String(), "UNAUTHORIZED",
				"body must contain UNAUTHORIZED for %q", tc.name)
			assert.Empty(t, capturer.receivedPath,
				"upstream must NOT be reached for %q", tc.name)
		})
	}
}

// TestProxy_Logout_DeniesInvalidAuth verifies that /v1/auth/logout also requires
// a valid token and returns 401 without reaching the upstream on bad auth.
func TestProxy_Logout_DeniesInvalidAuth(t *testing.T) {
	pub, _, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tests := []struct {
		name          string
		authorization string
	}{
		{"no token", ""},
		{"garbage token", "Bearer not.a.jwt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capturer.receivedPath = ""

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/logout", http.NoBody)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"/v1/auth/logout must return 401 without valid token: %q", tc.name)
			assert.Contains(t, w.Body.String(), "UNAUTHORIZED")
			assert.Empty(t, capturer.receivedPath,
				"upstream must NOT be reached for logout without valid token: %q", tc.name)
		})
	}
}

// mintToken creates a token with explicit iat and exp timestamps.
func mintToken(t *testing.T, priv ed25519.PrivateKey, kid string, iat, exp time.Time) string {
	t.Helper()

	claims := &jwt.Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    jwt.Issuer,
			Subject:   "user-abc",
			Audience:  gojwt.ClaimStrings{jwt.Audience},
			IssuedAt:  gojwt.NewNumericDate(iat),
			ExpiresAt: gojwt.NewNumericDate(exp),
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

// mintTokenWithIssuer creates a token with a custom issuer.
func mintTokenWithIssuer(t *testing.T, priv ed25519.PrivateKey, kid, issuer string, now time.Time) string {
	t.Helper()

	claims := &jwt.Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-abc",
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

// tamperSignature replaces the signature segment of a JWT with zeroed bytes.
func tamperSignature(tokenStr string) string {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return tokenStr
	}
	// 64 bytes → 86 base64url chars (no padding).
	return parts[0] + "." + parts[1] + "." + strings.Repeat("A", 86)
}

// ─── Path normalization tests (Major finding 2) ────────────────────────────────
//
// These tests prove that the path forwarded to the upstream is the SAME cleaned path
// the internal-block guard validated. Before the fix, /api/user/v1/foo/../bar forwarded
// the literal "/v1/foo/../bar" with ".." unresolved; now it must forward "/v1/bar".

func TestProxy_PathNormalization(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "user-abc")

	tests := []struct {
		name         string
		publicPath   string
		expectedPath string // what the upstream should see
	}{
		{
			name:         "dot-dot traversal is cleaned before forwarding",
			publicPath:   "/api/user/v1/foo/../bar",
			expectedPath: "/v1/bar",
		},
		{
			name:         "double slash is collapsed before forwarding",
			publicPath:   "/api/user/v1//me",
			expectedPath: "/v1/me",
		},
		{
			name:         "clean path is forwarded as-is",
			publicPath:   "/api/user/v1/me",
			expectedPath: "/v1/me",
		},
		{
			name:         "nested dot-dot is fully resolved",
			publicPath:   "/api/user/v1/a/b/../../c",
			expectedPath: "/v1/c",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capturer.receivedPath = ""
			capturer.responseStatus = http.StatusOK

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.publicPath, http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tokenStr)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.expectedPath, capturer.receivedPath,
				"upstream path mismatch for %q", tc.publicPath)
		})
	}
}

// ─── Internal-path blocking tests ─────────────────────────────────────────────
//
// These tests verify the defense-in-depth guard that refuses to proxy any
// request whose resolved upstream path contains an "internal" segment.
// All requests go through the full Gin + Auth + Proxy stack to confirm that
// the block fires correctly at the proxy layer for every evasion variant.

// TestProxy_InternalPathBlocked is a table-driven test covering:
//   - direct /internal/ prefix
//   - /internal/ segment in the middle of the path
//   - URL-encoded %2finternal evasion
//   - ../ traversal that resolves to /internal/
//   - a normal public path that MUST NOT be blocked (regression guard)
func TestProxy_InternalPathBlocked(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "user-internal-test")

	tests := []struct {
		name            string
		publicPath      string
		wantStatus      int
		wantUpstreamHit bool // true iff we expect the upstream capturer to be reached
	}{
		{
			name:            "direct internal prefix is blocked",
			publicPath:      "/api/user/internal/v1/kyc/abc123/status",
			wantStatus:      http.StatusNotFound,
			wantUpstreamHit: false,
		},
		{
			name:            "internal segment in mid-path is blocked",
			publicPath:      "/api/user/v1/foo/internal/bar",
			wantStatus:      http.StatusNotFound,
			wantUpstreamHit: false,
		},
		{
			name:            "URL-encoded slash before internal is blocked",
			publicPath:      "/api/user/%2finternal/v1",
			wantStatus:      http.StatusNotFound,
			wantUpstreamHit: false,
		},
		{
			name:            "dot-dot traversal into internal is blocked",
			publicPath:      "/api/user/foo/../internal/v1/status",
			wantStatus:      http.StatusNotFound,
			wantUpstreamHit: false,
		},
		{
			name:            "capital-case Internal segment is blocked (case-insensitive)",
			publicPath:      "/api/user/Internal/v1/resource",
			wantStatus:      http.StatusNotFound,
			wantUpstreamHit: false,
		},
		{
			name:            "all-caps INTERNAL segment is blocked (case-insensitive)",
			publicPath:      "/api/user/INTERNAL/v1/resource",
			wantStatus:      http.StatusNotFound,
			wantUpstreamHit: false,
		},
		{
			name:            "normal public path is NOT blocked",
			publicPath:      "/api/user/v1/me",
			wantStatus:      http.StatusOK,
			wantUpstreamHit: true,
		},
		{
			name:            "internalize substring is NOT over-blocked",
			publicPath:      "/api/user/v1/internalize/resource",
			wantStatus:      http.StatusOK,
			wantUpstreamHit: true,
		},
		// M1 — Null-byte bypass: %00 decodes to \x00; /api/user/%00internal/v1
		// would make containsInternalSegment miss the segment "\x00internal" (EqualFold
		// returns false). The request MUST be rejected with 400 INVALID_PATH before
		// ever reaching the internal-segment guard or the upstream.
		{
			name:            "null-byte prefix before internal is rejected (M1)",
			publicPath:      "/api/user/%00internal/v1",
			wantStatus:      http.StatusBadRequest,
			wantUpstreamHit: false,
		},
		{
			name:            "null-byte suffix on internal segment is rejected (M1)",
			publicPath:      "/api/user/internal%00/v1",
			wantStatus:      http.StatusBadRequest,
			wantUpstreamHit: false,
		},
		// M2 — Trailing-dot bypass: path.Clean keeps "internal." verbatim but some
		// upstreams strip trailing dots and route to /internal/*.  The guard MUST
		// normalise "internal." → "internal" before comparing.
		{
			name:            "trailing-dot internal. segment is blocked (M2)",
			publicPath:      "/api/user/internal./v1/resource",
			wantStatus:      http.StatusNotFound,
			wantUpstreamHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset the capturer between sub-tests so we can detect upstream hits.
			capturer.receivedPath = ""
			capturer.responseStatus = http.StatusOK

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.publicPath, http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tokenStr)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code, "unexpected status for path %q", tc.publicPath)

			if tc.wantUpstreamHit {
				assert.NotEmpty(t, capturer.receivedPath,
					"expected upstream to be reached for public path %q", tc.publicPath)
			} else {
				assert.Empty(t, capturer.receivedPath,
					"upstream must NOT be reached for blocked path %q", tc.publicPath)
				// 404 body must not reveal that the endpoint exists (no "internal" keyword).
				assert.NotContains(t, w.Body.String(), "internal",
					"404 body must not reveal internal path details")
			}
		})
	}
}

// ─── M1-RESIDUAL — Double-encoded control sequence path rejection ─────────────
//
// These tests cover the double-encoding bypass not caught by the M1 NUL-byte check.
// %2500internal → url.PathUnescape → "%00internal" (literal 3-char string, NOT a
// NUL byte), so the M1 \x00 guard passes. A second-decode upstream would convert
// "%00internal" → "\x00internal" → strip NUL → "internal" and route to /internal/*.
//
// The guard catches this by scanning the decoded string for literal %00/%0a/%0d.
//
// A fresh router instance is used to avoid exhausting the IPRateLimiter burst
// (fallbackBurst = 10) that is shared across sub-tests in TestProxy_InternalPathBlocked.

func TestProxy_DoubleEncodedControlPathRejected(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "user-double-enc-test")

	tests := []struct {
		name       string
		publicPath string
	}{
		{
			name:       "double-encoded null %2500 before internal segment is rejected with 400",
			publicPath: "/api/user/%2500internal/v1",
		},
		{
			name:       "double-encoded CRLF %250d on internal segment is rejected with 400",
			publicPath: "/api/user/internal%250d/v1",
		},
		{
			name:       "double-encoded newline %250a on segment is rejected with 400",
			publicPath: "/api/user/internal%250a/v1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capturer.receivedPath = ""
			capturer.responseStatus = http.StatusOK

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.publicPath, http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tokenStr)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code,
				"double-encoded control sequence must return 400 INVALID_PATH for path %q", tc.publicPath)
			assert.Empty(t, capturer.receivedPath,
				"upstream must NOT be reached for double-encoded control path %q", tc.publicPath)
		})
	}
}

// ─── S3 — Missing normalized-path context key: upstream must NOT be reached ───
//
// This test verifies that the S3 guard in the Rewrite closure is not merely a
// cosmetic log+body-truncation: when the normalized-path context key is absent
// (as in a direct ServeHTTP call that bypasses Forward), the upstream is
// verifiably never contacted.
//
// Before this fix: req.Out.Body = http.NoBody alone did NOT abort the upstream
// dial — httputil.ReverseProxy still sent a request (with an empty body) to the
// upstream URL set by req.SetURL.
//
// After this fix: the Rewrite closure also sets req.Out.URL.Host = "" so the
// transport dial fails immediately (no host to connect to).  The ErrorHandler
// returns 502 BAD_GATEWAY.  The upstream capturer is never hit.
func TestProxy_MissingNormalizedPath_DoesNotReachUpstream(t *testing.T) {
	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	table := config.RouteTable{
		"user": config.UpstreamEntry{BaseURL: upstream.URL},
	}

	// Build a Registry directly — bypasses the full Gin/Auth stack.
	registry, err := proxy.New(table, 5)
	require.NoError(t, err)

	rp, ok := registry.ProxyForService("user")
	require.True(t, ok, "user service must be registered")

	// Craft a request WITHOUT the ctxKeyNormalizedPath value in its context.
	// This simulates a caller that drives the proxy's ServeHTTP directly,
	// bypassing Forward (which is the only code path that stashes the key).
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/me", http.NoBody)
	// Deliberately do NOT set ctxKeyNormalizedPath in req's context.

	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	// The upstream must NOT have been contacted.
	assert.Empty(t, capturer.receivedPath,
		"upstream must NOT be reached when normalized-path context key is absent")

	// The response must be non-2xx (ErrorHandler fires and returns 502).
	assert.NotEqual(t, http.StatusOK, w.Code,
		"response must not be 200 OK when normalized-path context key is absent")
	assert.Equal(t, http.StatusBadGateway, w.Code,
		"missing context key must produce 502 BAD_GATEWAY via ErrorHandler")
}

// ─── Fix: protected route requires auth ──────────────────────────────────────

// TestProxy_ProtectedRouteRequiresAuth verifies that GET /api/user/v1/me without
// an Authorization header is rejected with 401 UNAUTHORIZED before the upstream
// is contacted. This covers the re-review finding requiring an explicit test for
// the deny-by-default auth wiring on protected proxy routes.
func TestProxy_ProtectedRouteRequiresAuth(t *testing.T) {
	pub, _, kid := generateEdDSAKey(t)

	capturer := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer)
	defer upstream.Close()

	routerCfg := buildRouter(t, pub, kid, upstream.URL)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/v1/me", http.NoBody)
	// No Authorization header set.

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"GET /api/user/v1/me without Authorization must return 401")
	assert.Contains(t, w.Body.String(), "UNAUTHORIZED",
		"401 body must contain machine-readable UNAUTHORIZED code")
	assert.Empty(t, capturer.receivedPath,
		"upstream must NOT be reached when Authorization header is missing")
}

// ─── M4 — HMAC canonical string: method + path + body binding (rev2-B) ──────
//
// Security-engineer finding M4 noted that the old HMAC canonical string did NOT
// bind the HTTP method or request path. That debt has been resolved in task
// 6-12-hmac-canonical: all 8 services (gateway signer + 7 downstream verifiers)
// now use the §24.1 rev2-B canonical string:
//
//	{len(method)}\n{method}\n{len(path)}\n{path}\n{len(bodyHashHex)}\n{bodyHashHex}\n
//	{userId}|{kycTier}|{accountType}|{emailVerified}|{requestId}|{ts}
//
// TestProxy_HMACSignaturePathBound asserts the NEW (correct) behavior:
// two requests with the same identity but DIFFERENT method and path MUST produce
// DIFFERENT X-Gateway-Signature values — proving the canonical string NOW binds method
// and path (cross-endpoint replay prevention).
func TestProxy_HMACSignaturePathBound(t *testing.T) {
	pub, priv, kid := generateEdDSAKey(t)

	capturer1 := &upstreamCapturer{}
	upstream := httptest.NewServer(capturer1)
	defer upstream.Close()

	// Use a fixed test HMAC signing key (32+ chars, test-only, not a real credential).
	testHMACKey := []byte("proxy-test-hmac-signing-key-0123456789ABCDEF")
	routerCfg := buildRouterWithHMAC(t, pub, kid, upstream.URL, testHMACKey)
	r, err := handler.NewRouter(routerCfg)
	require.NoError(t, err)

	tokenStr := signTestToken(t, priv, kid, "user-m4-test")

	// Request 1: GET /api/user/v1/profile
	capturer1.receivedHeaders = nil
	capturer1.receivedPath = ""
	req1 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/v1/profile", http.NoBody)
	req1.Header.Set("Authorization", "Bearer "+tokenStr)
	req1.Header.Set("X-Request-ID", "fixed-request-id-m4-001") // same request-id on both
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code, "request 1 must succeed")
	sig1 := capturer1.receivedHeaders.Get("X-Gateway-Signature")
	require.NotEmpty(t, sig1, "X-Gateway-Signature must be set on request 1")

	// Request 2: POST /api/user/v1/other — different method AND path, same identity
	capturer1.receivedHeaders = nil
	capturer1.receivedPath = ""
	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/user/v1/other", strings.NewReader("{}"))
	req2.Header.Set("Authorization", "Bearer "+tokenStr)
	req2.Header.Set("X-Request-ID", "fixed-request-id-m4-001") // intentionally the same
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code, "request 2 must succeed")
	sig2 := capturer1.receivedHeaders.Get("X-Gateway-Signature")
	require.NotEmpty(t, sig2, "X-Gateway-Signature must be set on request 2")

	// rev2-B ASSERTION: the HMAC canonical string now includes method, path, and body hash.
	// Two requests with the same identity/request-id but DIFFERENT method+path MUST
	// produce DIFFERENT signatures — cross-endpoint replay is prevented.
	assert.NotEqual(t, sig1, sig2,
		"rev2-B: X-Gateway-Signature must DIFFER for requests with different method/path "+
			"(method and path are now bound in the canonical string, closing M4 security debt)")
}

// ─── Cross-repo lockstep test: gateway signer path == downstream verifier path ─
//
// This is THE test that was missing and caused the C-1 bug to ship.
//
// Bug: the gateway signer used URL.RequestURI() = /api/file/v1/files (gateway-side
// path), but the downstream verifier used URL.RequestURI() = /v1/files (post-strip
// path, what the proxy forwarded). Different paths → different HMAC → 401 on every
// /api/:svc/* request in production.
//
// Fix: the gateway signer now strips the /api/<svc> prefix BEFORE signing, using
// the same proxy.UpstreamPathForSigning logic the proxy uses for forwarding.
//
// Downstream-verifier canonical (ref: file/internal/platform/middleware/gateway_signature.go):
//
//	{len(method)}\n{method}\n{len(path)}\n{path}\n{len(bodyHashHex)}\n{bodyHashHex}\n
//	{userId}|{kycTier}|{accountType}|{emailVerified}|{requestId}|{ts}
//
// where path = URL.RequestURI() on the downstream side = post-strip path.
//
// Each sub-test covers one of the three route shapes:
// (a) /api/:svc/* — path gets stripped (the bug case)
// (b) /api/file/v1/files — upload route, empty-body sentinel, path also stripped
// (c) /v1/me/* — path NOT stripped (already the final path)

// downstreamCanonical rebuilds the §24.1 rev2-B canonical string exactly as a
// downstream verifier would, given the downstream-side path (post-strip) and
// a pre-computed body hash.
func downstreamCanonical(method, downstreamPath, bodyHashHex,
	userID, kycTier, accountType, emailVerified, requestID, ts string,
) string {
	return fmt.Sprintf(
		"%d\n%s\n%d\n%s\n%d\n%s\n%s",
		len(method), method,
		len(downstreamPath), downstreamPath,
		len(bodyHashHex), bodyHashHex,
		strings.Join([]string{userID, kycTier, accountType, emailVerified, requestID, ts}, "|"),
	)
}

// computeHMAC returns hex(HMAC-SHA256(secret, msg)).
func computeHMAC(secret []byte, msg string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(msg))

	return hex.EncodeToString(mac.Sum(nil))
}

// buildRouterWithHMACAndServices builds a RouterConfig with the given services.
// mirrors buildRouterWithHMAC but accepts a map of service names → upstream URLs.
func buildRouterWithHMACAndServices(
	t *testing.T,
	pub ed25519.PublicKey, kid string,
	services map[string]string,
	hmacSecret []byte,
) *handler.RouterConfig {
	t.Helper()

	x := base64.RawURLEncoding.EncodeToString(pub)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"` + kid + `","x":"` + x + `"}]}`))
	}))
	t.Cleanup(jwksServer.Close)

	cache := jwks.NewCache(jwksServer.URL, 5*time.Minute, 5*time.Second)
	cache.Start(t.Context())

	verifier := jwt.NewVerifier(cache, "coverones-user", "coverones", 60)

	table := make(config.RouteTable, len(services))
	for svc, url := range services {
		table[svc] = config.UpstreamEntry{BaseURL: url}
	}

	return &handler.RouterConfig{
		Verifier:            verifier,
		JWKSCache:           cache,
		RouteTable:          table,
		ProxyTimeout:        5,
		RateLimitPerMin:     100_000,
		AuthRateLimitPerMin: 100_000,
		UserRateLimitPerMin: 100_000,
		UserRateLimitBurst:  100_000,
		HMACSecret:          hmacSecret,
	}
}

// TestProxy_CrossRepoLockstep_SignerPathMatchesVerifierPath is the regression
// test for C-1. It MUST fail against the buggy code (gateway signs over
// /api/file/v1/files) and MUST pass after the fix (gateway signs over /v1/files).
//
// The test uses the real router (handler.NewRouter) with a real upstream capturer
// so the signature that ends up in X-Gateway-Signature was produced by the actual
// InjectIdentity middleware, then recomputes the canonical the way a downstream
// verifier would and asserts they produce the same HMAC.
func TestProxy_CrossRepoLockstep_SignerPathMatchesVerifierPath(t *testing.T) {
	t.Parallel()

	pub, priv, kid := generateEdDSAKey(t)
	testHMACKey := []byte("cross-repo-lockstep-test-hmac-key-0123456789")

	const emptyBodyHashHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name string
		// Gateway-side values (what the client sends to the gateway).
		gatewayPath string
		method      string
		body        []byte
		// Downstream-side path (what the proxy forwards after stripping /api/<svc>).
		downstreamPath string
		// bodyHashHex for the downstream canonical.
		// For upload routes: emptyBodyHashHex. For others: sha256(body).
		bodyHashHex func(body []byte) string
	}{
		{
			name:           "(a) normal /api/:svc/* route — path is stripped",
			gatewayPath:    "/api/user/v1/me",
			method:         http.MethodGet,
			body:           nil,
			downstreamPath: "/v1/me",
			bodyHashHex: func(body []byte) string {
				h := sha256.Sum256(body)
				return hex.EncodeToString(h[:])
			},
		},
		{
			name:           "(b) upload route /api/file/v1/files — path stripped + empty-body sentinel",
			gatewayPath:    "/api/file/v1/files",
			method:         http.MethodPost,
			body:           []byte("large-multipart-body-that-is-not-read"),
			downstreamPath: "/v1/files",
			bodyHashHex: func(_ []byte) string {
				return emptyBodyHashHex // upload route always uses the sentinel
			},
		},
		{
			name:           "(c) /v1/me/* route — path NOT stripped",
			gatewayPath:    "/v1/me/profile",
			method:         http.MethodGet,
			body:           nil,
			downstreamPath: "/v1/me/profile", // same: no /api/<svc> prefix present
			bodyHashHex: func(body []byte) string {
				h := sha256.Sum256(body)
				return hex.EncodeToString(h[:])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			capturer := &upstreamCapturer{responseStatus: http.StatusOK}
			upstream := httptest.NewServer(capturer)
			defer upstream.Close()

			// All tests need both "user" (for /v1/me/* and /api/user/*) and
			// "file" (for /api/file/v1/files). Using the multi-service helper
			// ensures the route table covers all three test cases.
			routerCfg := buildRouterWithHMACAndServices(t, pub, kid, map[string]string{
				"user": upstream.URL,
				"file": upstream.URL,
			}, testHMACKey)
			r, err := handler.NewRouter(routerCfg)
			require.NoError(t, err)

			tokenStr := signTestToken(t, priv, kid, "lockstep-user-sub")

			const fixedRequestID = "req-lockstep-fixed-001"
			var reqBody *strings.Reader
			if tc.body != nil {
				reqBody = strings.NewReader(string(tc.body))
			} else {
				reqBody = strings.NewReader("")
			}

			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.gatewayPath, reqBody)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			req.Header.Set("X-Request-ID", fixedRequestID)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code,
				"router must reach upstream for %q", tc.gatewayPath)

			gotSig := capturer.receivedHeaders.Get("X-Gateway-Signature")
			require.NotEmpty(t, gotSig, "X-Gateway-Signature must be set")

			ts := capturer.receivedHeaders.Get("X-Gateway-Ts")
			require.NotEmpty(t, ts, "X-Gateway-Ts must be set")

			// Read the injected identity headers (what the downstream verifier will see).
			userID := capturer.receivedHeaders.Get("X-User-Id")
			kycTier := capturer.receivedHeaders.Get("X-Kyc-Tier")
			acctType := capturer.receivedHeaders.Get("X-Account-Type")
			emailVerif := capturer.receivedHeaders.Get("X-Email-Verified")
			requestID := capturer.receivedHeaders.Get("X-Request-ID")

			// Compute the body hash the way the downstream verifier would.
			bodyHashHex := tc.bodyHashHex(tc.body)

			// Rebuild the canonical string exactly as a downstream verifier does —
			// using the POST-STRIP (downstream) path, NOT the gateway-side path.
			canonical := downstreamCanonical(tc.method, tc.downstreamPath, bodyHashHex,
				userID, kycTier, acctType, emailVerif, requestID, ts)

			wantSig := computeHMAC(testHMACKey, canonical)

			assert.Equal(t, wantSig, gotSig,
				"[C-1 lockstep] gateway signer HMAC must equal the downstream verifier HMAC: "+
					"gateway signed over %q, downstream verifies over %q",
				tc.gatewayPath, tc.downstreamPath)

			// Sanity: recompute over the GATEWAY-SIDE path to prove it does NOT match —
			// this assertion documents the pre-fix bug and would PASS if the bug were
			// reintroduced (the gateway path != downstream path for /api/:svc/* routes).
			if tc.gatewayPath != tc.downstreamPath {
				wrongCanonical := downstreamCanonical(tc.method, tc.gatewayPath, bodyHashHex,
					userID, kycTier, acctType, emailVerif, requestID, ts)
				wrongSig := computeHMAC(testHMACKey, wrongCanonical)
				assert.NotEqual(t, wrongSig, gotSig,
					"[C-1 regression] signature over gateway-side path MUST NOT match — "+
						"if this fails the C-1 bug was reintroduced (gateway path != downstream path)")
			}

			// Parse and validate ts (sanity check on the signing output).
			_, err = strconv.ParseInt(ts, 10, 64)
			assert.NoError(t, err, "X-Gateway-Ts must be a valid Unix timestamp")
		})
	}
}
