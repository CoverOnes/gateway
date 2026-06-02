// Package health provides liveness and readiness check helpers for the gateway service.
package health

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ReadyChecker is implemented by types that can report readiness.
type ReadyChecker interface {
	Ready() bool
}

// Handler provides /healthz and /readyz gin handler functions.
type Handler struct {
	jwks ReadyChecker
}

// NewHandler returns a health handler backed by the JWKS cache readiness.
func NewHandler(jwks ReadyChecker) *Handler {
	return &Handler{jwks: jwks}
}

// Liveness always returns 200 if the process is serving (zero dependency checks).
func (h *Handler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Readiness checks whether the JWKS cache has at least one key loaded.
// Returns 200 {status:ready} or 503 {status:not_ready}.
// JWKS cache readiness is the only dependency for this stateless gateway.
func (h *Handler) Readiness(c *gin.Context) {
	checks := gin.H{}

	if h.jwks.Ready() {
		checks["jwks"] = "ok"
		c.JSON(http.StatusOK, gin.H{"status": "ready", "checks": checks})

		return
	}

	checks["jwks"] = "not_ready"
	c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "checks": checks})
}
