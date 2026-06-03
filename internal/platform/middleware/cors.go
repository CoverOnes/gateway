package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that adds Cross-Origin Resource Sharing headers.
// allowedOrigins is the list of exact origins permitted (e.g. "http://localhost:5500").
// An empty list disables CORS headers entirely (production default — CDN/reverse-proxy handles it).
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		// Defense-in-depth: never honor wildcard or null origins — combining "*"/"null"
		// with Access-Control-Allow-Credentials:true is a CWE-942 vulnerability. "null" is
		// browser-sent from sandboxed iframes / file:// contexts.
		if o == "" || o == "*" || strings.EqualFold(o, "null") {
			continue
		}
		allowed[o] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		if _, ok := allowed[origin]; !ok {
			c.Next()
			return
		}

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
		c.Header("Access-Control-Max-Age", "3600")
		c.Header("Vary", "Origin")

		// Handle preflight OPTIONS immediately — no further processing needed.
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
