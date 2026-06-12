package middleware_test

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/CoverOnes/gateway/internal/platform/middleware"
	"github.com/gin-gonic/gin"
)

// testHMACSecret is a fixed >=32-char secret used to assert the gateway-origin
// signature is computed deterministically. Test-only; not a real credential.
const testHMACSecret = "test-gateway-hmac-secret-0123456789ABCDEF"

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

	return setupIdentityTestRouterWithSecret(t, pub, kid, nil)
}

// setupIdentityTestRouterWithSecret mirrors setupIdentityTestRouter but lets a test
// configure the gateway-origin HMAC secret. A nil/empty secret disables signing
// (development parity). RequestID() is registered so X-Request-ID is available to
// InjectIdentity for the canonical signing string (CONVENTIONS §24).
func setupIdentityTestRouterWithSecret(
	t *testing.T, pub ed25519.PublicKey, kid string, hmacSecret []byte,
) (*gin.Engine, *capturedRequest) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	resolver := &testKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	captured := &capturedRequest{}

	r := gin.New()
	r.Use(middleware.RequestID())
	protected := r.Group("/protected")
	protected.Use(middleware.Auth(verifier))
	protected.Use(middleware.InjectIdentity(hmacSecret))
	protected.GET("/resource", func(c *gin.Context) {
		captured.headers = c.Request.Header.Clone()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	return r, captured
}

// expectedSignature recomputes the gateway-origin HMAC the way a downstream
// service MUST (CONVENTIONS §24.1 rev2-B): hex(HMAC-SHA256(secret, canonicalString))
// where canonicalString uses length-prefix framing over (method, path, bodyHashHex)
// followed by the identity tuple pipe-delimited:
//
//	{len(method)}\n{method}\n{len(path)}\n{path}\n{len(bodyHashHex)}\n{bodyHashHex}\n
//	{userId}|{kycTier}|{accountType}|{emailVerified}|{requestId}|{ts}
//
// For GET requests with no body, body = nil → bodyHashHex = hex(SHA-256("")).
//
// The helpers in this test that call expectedSignature for GET /protected/resource with
// no body must use method="GET", path="/protected/resource", body=nil.
// path is always "/protected/resource" in the current test suite because that is the only
// registered route; it is kept explicit as a parameter for readability when adding future cases.
//
//nolint:unparam // path is "/protected/resource" in all current call sites; parameter retained for readability
func expectedSignature(
	secret []byte,
	method, path string,
	body []byte,
	userID, kycTier, accountType, emailVerified, requestID, ts string,
) string {
	bodyHashRaw := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHashRaw[:])

	canonical := fmt.Sprintf(
		"%d\n%s\n%d\n%s\n%d\n%s\n%s",
		len(method), method,
		len(path), path,
		len(bodyHashHex), bodyHashHex,
		strings.Join([]string{userID, kycTier, accountType, emailVerified, requestID, ts}, "|"),
	)

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical)) // hmac.Hash.Write never errors

	return hex.EncodeToString(mac.Sum(nil))
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

// TestInjectIdentity_GatewaySignatureMatchesExpectedHMAC asserts that, for a known
// secret and known injected header values, X-Gateway-Signature equals the HMAC the
// downstream verifier recomputes over the locked canonical string, and X-Gateway-Ts
// is present. It also proves the signature is computed over the SAME values the
// downstream reads (the injected JWT-derived values, not any client-supplied ones).
func TestInjectIdentity_GatewaySignatureMatchesExpectedHMAC(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "sig-test-kid"
	secret := []byte(testHMACSecret)
	tests := []struct {
		name          string
		kycTier       int16
		emailVerified bool
		wantTier      string
		wantEmailVerf string
	}{
		{name: "verified tier2", kycTier: 2, emailVerified: true, wantTier: "2", wantEmailVerf: "true"},
		{name: "unverified tier0", kycTier: 0, emailVerified: false, wantTier: "0", wantEmailVerf: "false"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, captured := setupIdentityTestRouterWithSecret(t, pub, kid, secret)
			tokenStr := generateTokenWithEmailVerified(t, priv, kid, "sig-user-sub", tc.kycTier, tc.emailVerified)

			const fixedRequestID = "req-sig-fixed-0001"
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			req.Header.Set("X-Request-ID", fixedRequestID) // deterministic canonical input
			req.Header.Set("X-Kyc-Tier", "9")              // forged — must NOT influence the signature

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)

			ts := captured.headers.Get("X-Gateway-Ts")
			require.NotEmpty(t, ts, "X-Gateway-Ts must be set on the signed protected path")
			tsInt, err := strconv.ParseInt(ts, 10, 64)
			require.NoError(t, err, "X-Gateway-Ts must be unix seconds")
			assert.InDelta(t, time.Now().Unix(), tsInt, 5, "X-Gateway-Ts must be ~now")

			// The signature MUST be computed over the injected (JWT-derived) values:
			// the real tier from the token, NOT the forged "9".
			// GET /protected/resource with no body → body=nil.
			want := expectedSignature(secret, http.MethodGet, "/protected/resource", nil, "sig-user-sub", tc.wantTier, "PERSONAL", tc.wantEmailVerf, fixedRequestID, ts)
			assert.Equal(t, want, captured.headers.Get("X-Gateway-Signature"),
				"X-Gateway-Signature must equal HMAC over the locked canonical string of the injected values")
			// Sanity: a signature over the forged tier must NOT match — proves we signed real values.
			forged := expectedSignature(secret, http.MethodGet, "/protected/resource", nil, "sig-user-sub", "9", "PERSONAL", tc.wantEmailVerf, fixedRequestID, ts)
			assert.NotEqual(t, forged, captured.headers.Get("X-Gateway-Signature"),
				"signature must not validate against forged client-supplied values")
		})
	}
}

// TestInjectIdentity_NoSecretDisablesSigning asserts the development parity path:
// with no configured secret, identity headers are still injected but NO gateway-origin
// signature headers are emitted.
func TestInjectIdentity_NoSecretDisablesSigning(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "no-secret-kid"
	r, captured := setupIdentityTestRouterWithSecret(t, pub, kid, nil) // signing disabled

	tokenStr := generateToken(t, priv, kid, "nosig-user", 1)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosig-user", captured.headers.Get("X-User-Id"),
		"identity headers must still be injected when signing is disabled")
	assert.Empty(t, captured.headers.Get("X-Gateway-Signature"),
		"no signature header when no secret is configured")
	assert.Empty(t, captured.headers.Get("X-Gateway-Ts"),
		"no timestamp header when no secret is configured")
}

// TestInjectIdentity_ClientSuppliedSignatureHeadersAreStripped asserts a client cannot
// pre-seed X-Gateway-Signature / X-Gateway-Ts: any inbound values MUST be stripped and
// replaced by the gateway's own freshly-computed values (CONVENTIONS §24).
func TestInjectIdentity_ClientSuppliedSignatureHeadersAreStripped(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "strip-sig-kid"
	secret := []byte(testHMACSecret)
	r, captured := setupIdentityTestRouterWithSecret(t, pub, kid, secret)

	const fixedRequestID = "req-strip-0002"
	tokenStr := generateToken(t, priv, kid, "strip-user", 1)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-Request-ID", fixedRequestID)
	// Attacker pre-seeds both gateway-origin headers with bogus values.
	req.Header.Set("X-Gateway-Ts", "9999999999")
	req.Header.Set("X-Gateway-Signature", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	ts := captured.headers.Get("X-Gateway-Ts")
	assert.NotEqual(t, "9999999999", ts,
		"client-supplied X-Gateway-Ts must be stripped, not forwarded")
	gotSig := captured.headers.Get("X-Gateway-Signature")
	assert.NotEqual(t,
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", gotSig,
		"client-supplied X-Gateway-Signature must be stripped, not forwarded")

	// The surviving signature must be the gateway's own over the real values.
	// GET /protected/resource with no body → body=nil.
	want := expectedSignature(secret, http.MethodGet, "/protected/resource", nil, "strip-user", "1", "PERSONAL", "true", fixedRequestID, ts)
	assert.Equal(t, want, gotSig,
		"surviving signature must be the gateway's own HMAC over injected values")
}

// TestStripIdentityHeaders_StripsClientGatewaySignatureOnPublicRoute asserts the
// global StripIdentityHeaders removes client-supplied X-Gateway-Signature / X-Gateway-Ts
// on public/unauthenticated routes too — the signature path never reaches an upstream
// from a public route, and a client can never pre-seed gateway-origin headers anywhere.
func TestStripIdentityHeaders_StripsClientGatewaySignatureOnPublicRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	captured := &capturedRequest{}
	r := gin.New()
	r.Use(middleware.StripIdentityHeaders())

	r.GET("/public/resource", func(c *gin.Context) {
		captured.headers = c.Request.Header.Clone()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/public/resource", http.NoBody)
	req.Header.Set("X-Gateway-Ts", "9999999999")
	req.Header.Set("X-Gateway-Signature", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, captured.headers.Get("X-Gateway-Ts"),
		"StripIdentityHeaders must remove client-supplied X-Gateway-Ts on public routes")
	assert.Empty(t, captured.headers.Get("X-Gateway-Signature"),
		"StripIdentityHeaders must remove client-supplied X-Gateway-Signature on public routes")
}

// TestInjectIdentity_EmptyFieldKeepsPipePositions asserts the empty-field rule: when an
// injected value is empty (here X-Account-Type from a token with no accountType claim),
// the canonical string keeps a stable empty field between the "|" separators, and the
// gateway signs over that exact layout.
func TestInjectIdentity_EmptyFieldKeepsPipePositions(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "empty-field-kid"
	secret := []byte(testHMACSecret)
	r, captured := setupIdentityTestRouterWithSecret(t, pub, kid, secret)

	// Token with an EMPTY accountType claim — injected X-Account-Type is "".
	now := time.Now().UTC()
	claims := gojwt.MapClaims{
		"iss":            jwt.Issuer,
		"sub":            "empty-acct-user",
		"aud":            jwt.Audience,
		"iat":            now.Unix(),
		"exp":            now.Add(10 * time.Minute).Unix(),
		"kycTier":        1,
		"accountType":    "", // empty field on purpose
		"email_verified": true,
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	tokenStr, err := token.SignedString(priv)
	require.NoError(t, err)

	const fixedRequestID = "req-empty-0003"
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-Request-ID", fixedRequestID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, captured.headers.Get("X-Account-Type"),
		"account type must be the empty injected value for this token")

	ts := captured.headers.Get("X-Gateway-Ts")
	require.NotEmpty(t, ts)
	// Canonical string has an empty 3rd field but the "|" positions are preserved.
	// GET /protected/resource with no body → body=nil.
	want := expectedSignature(secret, http.MethodGet, "/protected/resource", nil, "empty-acct-user", "1", "", "true", fixedRequestID, ts)
	assert.Equal(t, want, captured.headers.Get("X-Gateway-Signature"),
		"empty field must keep its | position in the canonical string")
}

// setupIdentityTestRouterWithPost builds a router with GET + POST /protected/resource.
func setupIdentityTestRouterWithPost(t *testing.T, pub ed25519.PublicKey, kid string, hmacSecret []byte) (*gin.Engine, *capturedRequest) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	resolver := &testKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	verifier := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	captured := &capturedRequest{}

	r := gin.New()
	r.Use(middleware.RequestID())
	protected := r.Group("/protected")
	protected.Use(middleware.Auth(verifier))
	protected.Use(middleware.InjectIdentity(hmacSecret))
	protected.GET("/resource", func(c *gin.Context) {
		captured.headers = c.Request.Header.Clone()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	protected.POST("/resource", func(c *gin.Context) {
		captured.headers = c.Request.Header.Clone()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	return r, captured
}

// TestInjectIdentity_Rev2B_MethodAndBodyBound asserts that the gateway signer binds
// both the HTTP method and the request body into the canonical string (rev2-B additions
// over the earlier identity-tuple-only rev1).
//
// A GET signature must NOT pass for a POST to the same path (method-swap).
// A POST signature over body A must NOT pass for body B (body-tamper).
func TestInjectIdentity_Rev2B_MethodAndBodyBound(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "rev2b-test-kid"
	secret := []byte(testHMACSecret)
	r, captured := setupIdentityTestRouterWithPost(t, pub, kid, secret)

	tokenStr := generateToken(t, priv, kid, "rev2b-user", 1)
	const fixedRequestID = "req-rev2b-0004"

	t.Run("POST body is bound in canonical — different body changes signature", func(t *testing.T) {
		body := []byte(`{"amount":100}`)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/protected/resource",
			strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		req.Header.Set("X-Request-ID", fixedRequestID)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		ts := captured.headers.Get("X-Gateway-Ts")
		require.NotEmpty(t, ts)

		// Signature over the body that was actually sent.
		wantWithBody := expectedSignature(secret, http.MethodPost, "/protected/resource", body, "rev2b-user", "1", "PERSONAL", "true", fixedRequestID, ts)
		assert.Equal(t, wantWithBody, captured.headers.Get("X-Gateway-Signature"),
			"signer must compute HMAC over the actual POST body (rev2-B body binding)")

		// Signature over a different body must NOT match.
		wantWrongBody := expectedSignature(
			secret, http.MethodPost, "/protected/resource",
			[]byte(`{"amount":9999}`),
			"rev2b-user", "1", "PERSONAL", "true", fixedRequestID, ts,
		)
		assert.NotEqual(t, wantWrongBody, captured.headers.Get("X-Gateway-Signature"),
			"signature must not match a different body (rev2-B body binding prevents body tamper)")
	})

	t.Run("GET signature is NOT identical to POST signature (method bound)", func(t *testing.T) {
		// GET request.
		getReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", http.NoBody)
		getReq.Header.Set("Authorization", "Bearer "+tokenStr)
		getReq.Header.Set("X-Request-ID", fixedRequestID)

		wGet := httptest.NewRecorder()
		r.ServeHTTP(wGet, getReq)
		require.Equal(t, http.StatusOK, wGet.Code)

		getTs := captured.headers.Get("X-Gateway-Ts")
		getSig := captured.headers.Get("X-Gateway-Signature")

		// POST request (same path, no body for simplicity).
		postReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/protected/resource", http.NoBody)
		postReq.Header.Set("Authorization", "Bearer "+tokenStr)
		postReq.Header.Set("X-Request-ID", fixedRequestID)

		wPost := httptest.NewRecorder()
		r.ServeHTTP(wPost, postReq)
		require.Equal(t, http.StatusOK, wPost.Code)

		postTs := captured.headers.Get("X-Gateway-Ts")
		postSig := captured.headers.Get("X-Gateway-Signature")

		// Verify each signature matches its respective method.
		wantGet := expectedSignature(secret, http.MethodGet, "/protected/resource", nil, "rev2b-user", "1", "PERSONAL", "true", fixedRequestID, getTs)
		wantPost := expectedSignature(secret, http.MethodPost, "/protected/resource", nil, "rev2b-user", "1", "PERSONAL", "true", fixedRequestID, postTs)

		assert.Equal(t, wantGet, getSig, "GET signer must produce a method=GET canonical")
		assert.Equal(t, wantPost, postSig, "POST signer must produce a method=POST canonical")
		assert.NotEqual(t, wantGet, wantPost, "GET and POST signatures must differ (method is bound)")
	})
}
