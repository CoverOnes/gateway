package middleware

import (
	"log/slog"
	"net/http"

	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/CoverOnes/gateway/internal/platform/httpx"
	"github.com/CoverOnes/gateway/internal/platform/logger"
	"github.com/gin-gonic/gin"
)

// SSEAuth validates a JWT supplied via the access_token query parameter and
// injects claims into context identically to the Bearer Auth middleware.
//
// This middleware exists ONLY because browser EventSource cannot send an
// Authorization header. It MUST be registered on exactly one route:
//
//	GET /api/chat/v1/messages/stream
//
// Security properties:
//   - The token is validated by the same JWKS verifier as Auth() — identical
//     cryptographic standard and claim set.
//   - The token value is NEVER logged (it would appear in access logs otherwise).
//   - The route name is intentionally narrow: enabling query-param auth globally
//     is a security anti-pattern (tokens in URLs are logged by proxies, leak in
//     browser history, and in Referer headers). Scope must never widen.
//
// SCOPING RED-LINE: do NOT reuse this middleware on any route other than the
// chat SSE stream endpoint. All other routes MUST use the Bearer Auth() middleware.
func SSEAuth(verifier *jwt.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Redact the token from the URL immediately so it does not appear in
		// gin access logs. We read it before any logger middleware can capture
		// the raw URL. The query param is removed in-place on the parsed URL.
		token := c.Query("access_token")
		if token == "" {
			c.Abort()
			httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "access_token query parameter required")

			return
		}

		// Remove the token from the URL so downstream handlers and log middleware
		// never see the raw token value. This does NOT affect the query string
		// after the param is consumed — room_id (the only other SSE param) is
		// forwarded unchanged.
		//
		// We intentionally do not strip access_token from the forwarded request:
		// the chat-gateway never reads it (identity comes from X-User-Id after
		// InjectIdentity runs), but leaving it in would cause chat-gateway's
		// signature verifier to include it in the signed path, which the gateway
		// signer does NOT include. The gateway signer signs over the UPSTREAM path
		// (post /api/chat strip), which for the SSE route is /v1/messages/stream?room_id=...
		// (access_token already stripped by proxy.UpstreamPathForSigning's normal
		// path processing, but we also sanitize it here at the URL level so the
		// path handed to InjectIdentity is clean).
		q := c.Request.URL.Query()
		q.Del("access_token")
		c.Request.URL.RawQuery = q.Encode()

		claims, err := verifier.Verify(token)
		if err != nil {
			slog.Warn("sse: jwt verification failed", "err", err)
			// Do NOT log or echo the token value.
			c.Abort()
			httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")

			return
		}

		c.Set(ctxKeyClaims, claims)
		// Set "svc" so that InjectIdentity strips the correct /api/<svc> prefix
		// when computing the HMAC-signed path — the SSE route is not registered
		// under /api/:svc/* so c.Param("svc") would be empty otherwise.
		c.Set("svc", "chat")
		c.Request = c.Request.WithContext(
			logger.WithUserID(c.Request.Context(), claims.Subject),
		)
		c.Next()
	}
}
