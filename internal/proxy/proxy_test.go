package proxy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
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
		Verifier:     verifier,
		JWKSCache:    cache,
		RouteTable:   table,
		ProxyTimeout: 5,
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
			name:            "normal public path is NOT blocked",
			publicPath:      "/api/user/v1/me",
			wantStatus:      http.StatusOK,
			wantUpstreamHit: true,
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
