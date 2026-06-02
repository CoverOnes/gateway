package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/CoverOnes/gateway/internal/platform/httpx"
	"github.com/CoverOnes/gateway/internal/platform/logger"
	"github.com/gin-gonic/gin"
)

const ctxKeyClaims = "jwt_claims"

// Auth verifies the Bearer JWT from the Authorization header and injects claims into context.
// Deny-by-default: every protected route must be wrapped with this middleware.
// All error responses use the httpx envelope shape.
func Auth(verifier *jwt.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Abort()
			httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authorization header required")

			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.Abort()
			httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "bearer token required")

			return
		}

		claims, err := verifier.Verify(parts[1])
		if err != nil {
			slog.Warn("jwt verification failed", "err", err)
			c.Abort()
			httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")

			return
		}

		c.Set(ctxKeyClaims, claims)
		c.Request = c.Request.WithContext(
			logger.WithUserID(c.Request.Context(), claims.Subject),
		)
		c.Next()
	}
}

// RequireTier returns a middleware that enforces a minimum KYC tier.
// Must be registered after Auth middleware.
func RequireTier(minTier int16) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := c.Get(ctxKeyClaims)
		if !ok {
			c.Abort()
			httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")

			return
		}

		claims, ok := raw.(*jwt.Claims)
		if !ok {
			c.Abort()
			httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")

			return
		}

		if claims.KYCTier < minTier {
			c.Abort()
			httpx.ErrCode(
				c, http.StatusForbidden, "KYC_TIER_REQUIRED", "kyc verification required",
				gin.H{
					"requiredTier": minTier,
					"currentTier":  claims.KYCTier,
				},
			)

			return
		}

		c.Next()
	}
}

// ClaimsFromCtx extracts the JWT claims set by the Auth middleware.
func ClaimsFromCtx(c *gin.Context) (*jwt.Claims, bool) {
	raw, ok := c.Get(ctxKeyClaims)
	if !ok {
		return nil, false
	}

	claims, ok := raw.(*jwt.Claims)

	return claims, ok
}
