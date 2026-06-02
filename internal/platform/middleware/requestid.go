package middleware

import (
	"regexp"

	"github.com/CoverOnes/gateway/internal/platform/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const headerRequestID = "X-Request-ID"

// requestIDPattern accepts only safe characters to prevent header/log injection.
// Allows [A-Za-z0-9_-], maximum 64 characters.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,64}$`)

// RequestID reads or generates a request ID and attaches it to context + response header.
// Client-supplied X-Request-ID values are validated against requestIDPattern;
// invalid values are replaced with a fresh UUID to prevent header/log injection.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader(headerRequestID)
		if rid == "" || !requestIDPattern.MatchString(rid) {
			// Either missing or contains unsafe characters — generate a safe UUID.
			rid = uuid.New().String()
		}

		c.Set("request_id", rid)
		c.Header(headerRequestID, rid)
		c.Request = c.Request.WithContext(
			logger.WithRequestID(c.Request.Context(), rid),
		)
		c.Next()
	}
}
