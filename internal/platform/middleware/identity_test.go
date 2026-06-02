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

	now := time.Now().UTC()
	claims := &jwt.Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    jwt.Issuer,
			Subject:   sub,
			Audience:  gojwt.ClaimStrings{jwt.Audience},
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		KYCTier:     kycTier,
		AccountType: "PERSONAL",
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
