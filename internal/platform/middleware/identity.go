package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Gateway-origin signature headers (CONVENTIONS §24). The gateway HMAC-signs the
// injected identity tuple so downstream services can prove the identity headers
// came from the gateway, not from anything that can reach the service port on the
// internal network. Defense-in-depth layered on the gateway-sole-JWT-verifier
// model — NOT a replacement.
const (
	headerGatewayTs        = "X-Gateway-Ts"
	headerGatewaySignature = "X-Gateway-Signature"
)

// identityHeaders lists all client-supplied identity headers that MUST be stripped
// before forwarding to upstream services to prevent spoofing attacks.
//
// Implicit contract — strip-list vs inject-list are deliberately asymmetric:
//   - ALL headers below are STRIPPED on every request (StripIdentityHeaders +
//     InjectIdentity Step 1), so a client can never spoof any of them.
//   - Only X-User-Id, X-Kyc-Tier, X-Account-Type, and X-Email-Verified are
//     RE-INJECTED from the verified JWT claims (InjectIdentity Step 2). Upstreams
//     may trust these.
//   - X-User-Email and X-User-Role are intentionally NOT injected: the gateway
//     does not vouch for them. They appear here only to be stripped — upstreams
//     must NEVER treat an inbound X-User-Email / X-User-Role as authoritative,
//     because the gateway guarantees only their absence, not their value.
//
// If a future claim (e.g. email/role) becomes gateway-vouched, it MUST be added
// to InjectIdentity Step 2 below as well — adding it here alone only strips it.
//
// The two gateway-origin signature headers (X-Gateway-Ts, X-Gateway-Signature)
// are ALSO stripped on every request: a client must never be able to pre-seed
// them. Only InjectIdentity (Step 3) re-sets them, computed over the gateway's
// own injected values. A request that reaches an upstream with these headers set
// therefore proves they were produced by the gateway.
var identityHeaders = []string{
	"X-User-Id",
	"X-Kyc-Tier",
	"X-Account-Type",
	"X-Email-Verified",
	"X-User-Email",
	"X-User-Role",
	headerGatewayTs,
	headerGatewaySignature,
}

// StripIdentityHeaders removes all identity headers from the inbound request.
// It performs ONLY deletion — no values are set — making it safe to register
// globally on every route (including public ones).
//
// This provides defense-in-depth: even if a client sends X-User-Id on a public
// route (/v1/auth/login, /jwks, etc.), the upstream will never see it.
// Protected routes additionally run InjectIdentity (Del + Set from verified JWT claims).
func StripIdentityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, h := range identityHeaders {
			c.Request.Header.Del(h)
		}

		c.Next()
	}
}

// InjectIdentity strips any client-supplied identity headers and replaces them with
// values derived from the verified JWT claims. This is the anti-spoofing boundary.
//
// When hmacSecret is non-empty it ALSO sets the gateway-origin signature headers
// (X-Gateway-Ts, X-Gateway-Signature) so downstream services can verify the
// identity headers actually came from the gateway (CONVENTIONS §24). An empty
// secret disables signing — used in development only; non-dev config fails fast
// if the secret is unset (see config.validate).
//
// MUST run AFTER the Auth middleware — it reads claims from context.
// Routes without Auth do NOT get InjectIdentity (they forward no identity headers).
func InjectIdentity(hmacSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Step 1: STRIP all inbound identity headers (prevent client spoofing).
		for _, h := range identityHeaders {
			c.Request.Header.Del(h)
		}

		// Step 2: SET headers from verified JWT claims only.
		claims, ok := ClaimsFromCtx(c)
		if !ok {
			// Auth middleware should have rejected unauthenticated requests before
			// InjectIdentity runs. This is a belt-and-suspenders guard.
			c.Next()

			return
		}

		c.Request.Header.Set("X-User-Id", claims.Subject)
		c.Request.Header.Set("X-Kyc-Tier", strconv.Itoa(int(claims.KYCTier)))
		c.Request.Header.Set("X-Account-Type", claims.AccountType)
		// Fail-safe: an older token without the email_verified claim leaves
		// claims.EmailVerified at its zero value (false), so this injects
		// "false" — never an empty or "true" header for an unverified user.
		//
		// Cross-service string contract (TIGHT): the gateway emits the literal
		// "true"/"false" via strconv.FormatBool, and the kyc service gates on an
		// exact "true" match (kyc internal/platform/middleware/identity.go).
		// Neither side may drift to a different encoding (JSON bool / "1" / "True")
		// without breaking the email-verified gate.
		c.Request.Header.Set("X-Email-Verified", strconv.FormatBool(claims.EmailVerified))

		// Pin the canonical X-Request-ID onto the REQUEST header so the value the
		// gateway signs over is exactly the value the proxy forwards downstream
		// (proxy.go reads req.In.Header.Get("X-Request-ID")). RequestID() middleware
		// only writes the id to context + the response header, so without this an
		// inbound request with no/invalid X-Request-ID would forward an EMPTY value
		// downstream while we signed over the generated one — a guaranteed mismatch.
		// Pinning it here also fixes that latent propagation gap.
		rid := c.GetString("request_id")
		c.Request.Header.Set("X-Request-ID", rid)

		// Step 3: sign the injected identity tuple (defense-in-depth, CONVENTIONS §24).
		// Skipped when no secret is configured (development only).
		if len(hmacSecret) == 0 {
			c.Next()

			return
		}

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		c.Request.Header.Set(headerGatewayTs, ts)

		// Canonical string is locked by decision 2d8284a6: the literal VALUES of
		// these headers joined by "|" in EXACTLY this order. Empty value => empty
		// field, the "|" positions stay stable. Built from the FINAL injected
		// values so it matches byte-for-byte what downstream recomputes.
		canonical := strings.Join([]string{
			c.Request.Header.Get("X-User-Id"),
			c.Request.Header.Get("X-Kyc-Tier"),
			c.Request.Header.Get("X-Account-Type"),
			c.Request.Header.Get("X-Email-Verified"),
			rid,
			ts,
		}, "|")

		mac := hmac.New(sha256.New, hmacSecret)
		mac.Write([]byte(canonical))
		c.Request.Header.Set(headerGatewaySignature, hex.EncodeToString(mac.Sum(nil)))

		c.Next()
	}
}
