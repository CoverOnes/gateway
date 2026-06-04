package middleware

import (
	"strconv"

	"github.com/gin-gonic/gin"
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
var identityHeaders = []string{
	"X-User-Id",
	"X-Kyc-Tier",
	"X-Account-Type",
	"X-Email-Verified",
	"X-User-Email",
	"X-User-Role",
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
// MUST run AFTER the Auth middleware — it reads claims from context.
// Routes without Auth do NOT get InjectIdentity (they forward no identity headers).
func InjectIdentity() gin.HandlerFunc {
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
		c.Request.Header.Set("X-Email-Verified", strconv.FormatBool(claims.EmailVerified))

		c.Next()
	}
}
