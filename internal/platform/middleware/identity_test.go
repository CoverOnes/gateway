package middleware_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/CoverOnes/gateway/internal/platform/middleware"
	"github.com/gin-gonic/gin"
)

// capturedRequest records the headers as seen by the upstream handler.
type capturedRequest struct {
	headers http.Header
}

// testKeyResolver satisfies jwt.KeyResolver with a static map.
type testKeyResolver struct {
	keys map[string]ed25519.PublicKey
}

func (r *testKeyResolver) Get(kid string) (ed25519.PublicKey, error) {
	return r.keys[kid], nil
}

func setupIdentityTestRouter(t *testing.T, pub ed25519.PublicKey, kid string) (*gin.Engine, *capturedRequest) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	resolver := &testKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	captured := &capturedRequest{}

	r := gin.New()
	protected := r.Group("/protected")
	protected.Use(middleware.Auth(verifier))
	protected.Use(middleware.InjectIdentity())
	protected.GET("/resource", func(c *gin.Context) {
		captured.headers = c.Request.Header.Clone()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	return r, captured
}

func generateToken(t *testing.T, priv ed25519.PrivateKey, kid, sub string, kycTier int16) string {
	t.Helper()

	return generateTokenWithEmailVerified(t, priv, kid, sub, kycTier, true)
}

// generateTokenWithEmailVerified mirrors generateToken but lets a test control the
// email_verified claim, so the X-Email-Verified injection can be exercised for both
// verified and unverified users.
func generateTokenWithEmailVerified(
	t *testing.T, priv ed25519.PrivateKey, kid, sub string, kycTier int16, emailVerified bool,
) string {
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
		KYCTier:       kycTier,
		AccountType:   "PERSONAL",
		EmailVerified: emailVerified,
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	require.NoError(t, err)

	return signed
}

// generateLegacyToken builds a token whose raw JSON entirely OMITS the email_verified
// claim, simulating an older user-service release issued before auth Increment 1.
// It cannot use the Claims struct (which always serializes the field), so it signs a
// raw jwt.MapClaims with only the pre-Increment-1 fields present.
func generateLegacyToken(t *testing.T, priv ed25519.PrivateKey, kid, sub string) string {
	t.Helper()

	now := time.Now().UTC()
	claims := gojwt.MapClaims{
		"iss":         jwt.Issuer,
		"sub":         sub,
		"aud":         jwt.Audience,
		"iat":         now.Unix(),
		"exp":         now.Add(10 * time.Minute).Unix(),
		"kycTier":     0,
		"accountType": "PERSONAL",
		// email_verified deliberately absent.
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	require.NoError(t, err)

	return signed
}

func TestInjectIdentity_SpoofedHeaderIsStripped(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "identity-test-kid"
	r, captured := setupIdentityTestRouter(t, pub, kid)

	// Attacker supplies a spoofed X-User-Id.
	tokenStr := generateToken(t, priv, kid, "real-user-sub", 1)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-User-Id", "victim-user-id") // spoofed!

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// The spoofed header must be replaced with the real sub from the JWT.
	assert.Equal(t, "real-user-sub", captured.headers.Get("X-User-Id"),
		"X-User-Id must come from JWT claims, not client header")
	assert.NotEqual(t, "victim-user-id", captured.headers.Get("X-User-Id"),
		"spoofed X-User-Id must NOT reach upstream")
}

func TestInjectIdentity_KycTierInjectedFromClaims(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "identity-test-kid-2"
	r, captured := setupIdentityTestRouter(t, pub, kid)

	// Client sends a spoofed high-tier header.
	tokenStr := generateToken(t, priv, kid, "user-456", 0) // tier 0 in JWT

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-Kyc-Tier", "3") // spoofed high tier!

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// Tier must be 0 from JWT, not 3 from client.
	assert.Equal(t, "0", captured.headers.Get("X-Kyc-Tier"),
		"X-Kyc-Tier must reflect JWT claims, not spoofed client value")
}

func TestInjectIdentity_EmailVerifiedInjectedFromClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		emailVerf bool
		// spoofHeader is a client-supplied X-Email-Verified value that MUST be
		// overridden by the value derived from the verified JWT claim.
		spoofHeader string
		wantHeader  string
	}{
		{
			name:        "verified user yields true",
			emailVerf:   true,
			spoofHeader: "",
			wantHeader:  "true",
		},
		{
			name:        "unverified user yields false",
			emailVerf:   false,
			spoofHeader: "",
			wantHeader:  "false",
		},
		{
			name:        "spoofed true on unverified user is overridden to false",
			emailVerf:   false,
			spoofHeader: "true", // attacker forges a verified header
			wantHeader:  "false",
		},
		{
			name:        "spoofed false on verified user is overridden to true",
			emailVerf:   true,
			spoofHeader: "false",
			wantHeader:  "true",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			kid := "email-verified-test-kid"
			r, captured := setupIdentityTestRouter(t, pub, kid)

			tokenStr := generateTokenWithEmailVerified(t, priv, kid, "user-ev", 1, tc.emailVerf)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			if tc.spoofHeader != "" {
				req.Header.Set("X-Email-Verified", tc.spoofHeader)
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.wantHeader, captured.headers.Get("X-Email-Verified"),
				"X-Email-Verified must reflect the verified JWT claim, never the client header")
		})
	}
}

// TestInjectIdentity_LegacyTokenWithoutEmailVerifiedDefaultsFalse ensures the
// fail-safe default: a token issued before the email_verified claim existed must
// produce X-Email-Verified: false, never an empty or "true" header.
func TestInjectIdentity_LegacyTokenWithoutEmailVerifiedDefaultsFalse(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "legacy-token-test-kid"
	r, captured := setupIdentityTestRouter(t, pub, kid)

	tokenStr := generateLegacyToken(t, priv, kid, "legacy-user")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "false", captured.headers.Get("X-Email-Verified"),
		"older token without email_verified claim must fail safe to X-Email-Verified: false")
}

// TestInjectIdentity_NonCanonicalCaseSpoofIsStripped proves the strip is
// canonicalization-safe, not exact-case-only. An attacker who sets an identity
// header via the RAW header map (bypassing http.Header.Set's canonicalization)
// in lowercase or mixed-case must STILL have it overridden by the verified JWT
// claim. This documents the invariant against a future refactor that might read
// or write the raw map directly.
//
// The token is UNVERIFIED (email_verified=false), so a successful strip yields
// X-Email-Verified: false from the claim — never the spoofed "true".
func TestInjectIdentity_NonCanonicalCaseSpoofIsStripped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawHeader string // non-canonical key written straight into the raw map
	}{
		{name: "all lowercase", rawHeader: "x-email-verified"},
		{name: "mixed case", rawHeader: "X-Email-VERIFIED"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			kid := "noncanonical-spoof-test-kid"
			r, captured := setupIdentityTestRouter(t, pub, kid)

			// UNVERIFIED user — a correct strip must yield "false".
			tokenStr := generateTokenWithEmailVerified(t, priv, kid, "user-nc", 1, false)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			// Write directly into the raw map so the key is NOT canonicalized.
			// http.Header.Set would rewrite this to "X-Email-Verified"; we bypass it
			// to simulate an attacker (or a buggy proxy) emitting a non-canonical key.
			req.Header[tc.rawHeader] = []string{"true"} // spoofed verified header

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)

			// Canonical lookup must see only the claim-derived "false".
			assert.Equal(t, "false", captured.headers.Get("X-Email-Verified"),
				"non-canonical-case spoof must be stripped; X-Email-Verified must come from the unverified JWT claim")
			// And no stray non-canonical key may survive to the upstream.
			assert.NotContains(t, captured.headers.Values("X-Email-Verified"), "true",
				"spoofed verified value must never reach upstream under any header casing")
		})
	}
}

// TestInjectIdentity_NonCanonicalCaseUserIdSpoofIsStripped is the X-User-Id
// counterpart of the email-verified casing test: a non-canonical raw-map spoof
// of the user id must still be replaced by the JWT subject.
func TestInjectIdentity_NonCanonicalCaseUserIdSpoofIsStripped(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "noncanonical-userid-test-kid"
	r, captured := setupIdentityTestRouter(t, pub, kid)

	tokenStr := generateToken(t, priv, kid, "real-user-sub", 1)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	// Non-canonical raw-map spoof of X-User-Id.
	req.Header["x-user-id"] = []string{"victim-user-id"}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	assert.Equal(t, "real-user-sub", captured.headers.Get("X-User-Id"),
		"X-User-Id must come from JWT claims even when the spoof uses a non-canonical header key")
	assert.NotContains(t, captured.headers.Values("X-User-Id"), "victim-user-id",
		"non-canonical-case spoofed X-User-Id must never reach upstream")
}

func TestStripIdentityHeaders_PublicRouteDropsClientIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	captured := &capturedRequest{}
	r := gin.New()

	// Simulate global StripIdentityHeaders registered before routing.
	r.Use(middleware.StripIdentityHeaders())

	// Public route — no Auth, no InjectIdentity.
	r.GET("/public/resource", func(c *gin.Context) {
		captured.headers = c.Request.Header.Clone()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/public/resource", http.NoBody)
	req.Header.Set("X-User-Id", "attacker-id")  // spoofed
	req.Header.Set("X-Kyc-Tier", "3")           // spoofed
	req.Header.Set("X-Account-Type", "COMPANY") // spoofed

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	assert.Empty(t, captured.headers.Get("X-User-Id"),
		"StripIdentityHeaders must remove client-supplied X-User-Id on public routes")
	assert.Empty(t, captured.headers.Get("X-Kyc-Tier"),
		"StripIdentityHeaders must remove client-supplied X-Kyc-Tier on public routes")
	assert.Empty(t, captured.headers.Get("X-Account-Type"),
		"StripIdentityHeaders must remove client-supplied X-Account-Type on public routes")
}

func TestInjectIdentity_UnauthenticatedPathHasNoIdentityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	captured := &capturedRequest{}
	r := gin.New()

	// Simulate global StripIdentityHeaders (as registered in NewRouter).
	r.Use(middleware.StripIdentityHeaders())

	// Public route with NO auth or InjectIdentity middleware.
	r.GET("/public/resource", func(c *gin.Context) {
		captured.headers = c.Request.Header.Clone()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/public/resource", http.NoBody)
	req.Header.Set("X-User-Id", "attacker-id") // client tries to set identity

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// StripIdentityHeaders is global; the client-supplied header must be gone.
	assert.Empty(t, captured.headers.Get("X-User-Id"),
		"identity header must be stripped by StripIdentityHeaders before reaching public handler")
}
