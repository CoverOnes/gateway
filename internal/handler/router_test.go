package handler_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// recordingUpstreamStub starts an httptest server that records the exact path
// forwarded to it (the gateway must preserve /v1/auth/... paths verbatim for the
// user upstream). The last forwarded path is written to *gotPath. It replies 200
// to any request so the test can assert routing without provider integration.
func recordingUpstreamStub(t *testing.T, gotPath *string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.URL.Path
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

// ─── TestOAuthRoutesArePublic ─────────────────────────────────────────────────

// newTestRouterRecording builds a router whose "user" upstream is the recording
// stub, with generous rate limits so routing (not throttling) is under test.
func newTestRouterRecording(t *testing.T, gotPath *string) http.Handler {
	t.Helper()

	pub, _ := generateEdDSAKey(t)
	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{"oauth-test-kid": pub}}
	upstream := recordingUpstreamStub(t, gotPath)

	// High limits so nothing is rate-limited within a handful of requests.
	return newTestRouterWithIPRL(t, 6000, 6000, 100, 6000, resolver, upstream)
}

// TestOAuthRoutesArePublic proves the OAuth start/callback routes:
//   - are reachable WITHOUT an Authorization header (they ARE the auth flow),
//   - forward the exact /v1/auth/oauth/... path to the user upstream verbatim,
//   - accept both provider slugs via the :provider path param.
//
// A 401 would mean the route was accidentally placed behind Auth middleware;
// the recorded upstream path proves the gateway preserves the path for the
// provider-validation logic that lives in the user service.
func TestOAuthRoutesArePublic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		method       string
		path         string
		wantUpstream string // exact path the user upstream must receive
	}{
		{
			name:         "google start forwards verbatim, no auth",
			method:       http.MethodGet,
			path:         "/v1/auth/oauth/google/start",
			wantUpstream: "/v1/auth/oauth/google/start",
		},
		{
			name:         "line start forwards verbatim, no auth",
			method:       http.MethodGet,
			path:         "/v1/auth/oauth/line/start",
			wantUpstream: "/v1/auth/oauth/line/start",
		},
		{
			name:         "google callback forwards verbatim, no auth",
			method:       http.MethodGet,
			path:         "/v1/auth/oauth/google/callback?code=abc&state=xyz",
			wantUpstream: "/v1/auth/oauth/google/callback",
		},
		{
			name:         "line callback forwards verbatim, no auth",
			method:       http.MethodGet,
			path:         "/v1/auth/oauth/line/callback?error=access_denied&state=xyz",
			wantUpstream: "/v1/auth/oauth/line/callback",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotPath string
			r := newTestRouterRecording(t, &gotPath)

			// No bearer token: these routes MUST NOT require auth.
			code := doRouterRequest(t, r, tc.method, tc.path, "")

			require.NotEqual(t, http.StatusUnauthorized, code,
				"OAuth route must be public (got 401 — route is wrongly behind Auth middleware)")
			require.NotEqual(t, http.StatusNotFound, code,
				"OAuth route must be registered (got 404 — route not wired)")
			assert.Equal(t, http.StatusOK, code, "expected the user upstream stub to be reached (200)")
			assert.Equal(t, tc.wantUpstream, gotPath,
				"gateway must forward the OAuth path to the user upstream verbatim")
		})
	}
}

// TestOAuthRouteMethodMismatch proves the OAuth routes are GET-only. A POST to
// the start path must NOT reach the upstream as an OAuth start (gin returns 404
// for an unregistered method+path combination, since no POST handler exists there).
func TestOAuthRouteMethodMismatch(t *testing.T) {
	t.Parallel()

	var gotPath string
	r := newTestRouterRecording(t, &gotPath)

	// POST is not registered for the OAuth start route → gin 404 (no fallthrough to upstream).
	code := doRouterRequest(t, r, http.MethodPost, "/v1/auth/oauth/google/start", "")
	assert.Equal(t, http.StatusNotFound, code,
		"OAuth start is GET-only; POST must not be routed to the upstream")
	assert.Empty(t, gotPath, "upstream must NOT be reached for a non-GET OAuth start request")
}

// TestIdentitiesProxyRequiresAuth proves the Settings identities endpoints ride
// the existing protected /api/:svc proxy and therefore REQUIRE a valid access
// token. Without a bearer token the gateway must reject with 401 before any
// upstream involvement — confirming the contract's "no gateway change needed,
// the generic protected proxy already covers /api/user/v1/me/identities".
func TestIdentitiesProxyRequiresAuth(t *testing.T) {
	t.Parallel()

	identitiesPaths := []struct {
		name   string
		method string
		path   string
	}{
		{"list identities", http.MethodGet, "/api/user/v1/me/identities"},
		{"link start", http.MethodPost, "/api/user/v1/me/identities/google/link"},
		{"unlink", http.MethodDelete, "/api/user/v1/me/identities/line"},
	}

	for _, tc := range identitiesPaths {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotPath string
			r := newTestRouterRecording(t, &gotPath)

			// No bearer token: the protected proxy must reject with 401.
			code := doRouterRequest(t, r, tc.method, tc.path, "")
			assert.Equal(t, http.StatusUnauthorized, code,
				"identities endpoints must require auth (protected /api/:svc proxy)")
			assert.Empty(t, gotPath, "upstream must NOT be reached for an unauthenticated identities request")
		})
	}
}

// TestIdentitiesProxyForwardsWithAuth proves an authenticated identities request
// is forwarded to the user upstream with the /api/user prefix stripped (verbatim
// downstream path /v1/me/identities), via the existing protected proxy — no new
// gateway route was added for identities.
func TestIdentitiesProxyForwardsWithAuth(t *testing.T) {
	t.Parallel()

	pub, priv := generateEdDSAKey(t)
	const kid = "identities-test-kid"
	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}

	var gotPath string
	upstream := recordingUpstreamStub(t, &gotPath)
	r := newTestRouterWithIPRL(t, 6000, 6000, 100, 6000, resolver, upstream)

	token := mintToken(t, priv, kid, fmt.Sprintf("user-identities-%d", time.Now().UnixNano()))
	code := doRouterRequest(t, r, http.MethodGet, "/api/user/v1/me/identities", token)

	require.Equal(t, http.StatusOK, code, "authenticated identities request must reach the upstream")
	assert.Equal(t, "/v1/me/identities", gotPath,
		"gateway must strip /api/user and forward /v1/me/identities to the user upstream")
}
