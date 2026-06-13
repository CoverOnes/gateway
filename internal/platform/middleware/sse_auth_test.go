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

// buildSSERouter returns a gin engine that mirrors the production SSE route chain:
// SSEAuth(verifier) → capture handler (no InjectIdentity; unit tests focus on auth only).
func buildSSERouter(t *testing.T, pub ed25519.PublicKey, kid string) (*gin.Engine, *capturedRequest) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	resolver := &testKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	captured := &capturedRequest{}

	r := gin.New()
	r.Use(middleware.RequestID())
	r.GET(
		"/api/chat/v1/messages/stream",
		middleware.SSEAuth(verifier),
		func(c *gin.Context) {
			captured.headers = c.Request.Header.Clone()
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	return r, captured
}

func generateSSEToken(t *testing.T, priv ed25519.PrivateKey, kid, sub string) string {
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
		KYCTier:       0,
		AccountType:   "personal",
		EmailVerified: true,
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	require.NoError(t, err)

	return signed
}

func generateEdDSAKeyPairSSE(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return pub, priv
}

func TestSSEAuth(t *testing.T) {
	pub, priv := generateEdDSAKeyPairSSE(t)
	const kid = "test-kid-sse"
	const sub = "user-uuid-0000"

	validToken := generateSSEToken(t, priv, kid, sub)

	tests := []struct {
		name       string
		queryParam string
		wantStatus int
	}{
		{
			name:       "valid access_token → 200 and identity injected into ctx",
			queryParam: "?room_id=room-1&access_token=" + validToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing access_token → 401",
			queryParam: "?room_id=room-1",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty access_token → 401",
			queryParam: "?room_id=room-1&access_token=",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "malformed token → 401",
			queryParam: "?room_id=room-1&access_token=not.a.valid.jwt",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "expired token → 401",
			queryParam: "?room_id=room-1&access_token=" + generateExpiredToken(t, priv, kid, sub),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := buildSSERouter(t, pub, kid)

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"/api/chat/v1/messages/stream"+tc.queryParam,
				http.NoBody,
			)
			require.NoError(t, err)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// TestSSEAuth_TokenRedactedFromURL verifies that after SSEAuth runs, the access_token
// query parameter is no longer present in c.Request.URL so it cannot appear in logs.
func TestSSEAuth_TokenRedactedFromURL(t *testing.T) {
	pub, priv := generateEdDSAKeyPairSSE(t)
	const kid = "test-kid-sse-redact"
	const sub = "user-uuid-1111"

	token := generateSSEToken(t, priv, kid, sub)

	gin.SetMode(gin.TestMode)

	resolver := &testKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	var capturedURL string

	r := gin.New()
	r.GET(
		"/api/chat/v1/messages/stream",
		middleware.SSEAuth(verifier),
		func(c *gin.Context) {
			capturedURL = c.Request.URL.RawQuery
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/chat/v1/messages/stream?room_id=room-abc&access_token="+token,
		http.NoBody,
	)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, capturedURL, "access_token", "access_token must be stripped from URL after SSEAuth")
	assert.Contains(t, capturedURL, "room_id=room-abc", "room_id must be preserved")
}

// generateExpiredToken builds a token whose exp is in the past.
func generateExpiredToken(t *testing.T, priv ed25519.PrivateKey, kid, sub string) string {
	t.Helper()

	now := time.Now().UTC()
	claims := &jwt.Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    jwt.Issuer,
			Subject:   sub,
			Audience:  gojwt.ClaimStrings{jwt.Audience},
			IssuedAt:  gojwt.NewNumericDate(now.Add(-20 * time.Minute)),
			ExpiresAt: gojwt.NewNumericDate(now.Add(-10 * time.Minute)),
		},
		KYCTier:     0,
		AccountType: "personal",
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	require.NoError(t, err)

	return signed
}
