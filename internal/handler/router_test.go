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
