// Package handler wires up Gin routes for the gateway service.
package handler

import (
	"github.com/CoverOnes/gateway/internal/proxy"
	"github.com/gin-gonic/gin"
)

// ProxyHandler forwards requests to the appropriate upstream via the proxy registry.
type ProxyHandler struct {
	registry *proxy.Registry
}

// NewProxyHandler creates a ProxyHandler backed by the given Registry.
func NewProxyHandler(registry *proxy.Registry) *ProxyHandler {
	return &ProxyHandler{registry: registry}
}

// Forward extracts the :svc path parameter and delegates to the Registry.
// The Registry handles unknown services with 404 SERVICE_NOT_FOUND.
func (h *ProxyHandler) Forward(c *gin.Context) {
	svc := c.Param("svc")
	h.registry.Forward(c, svc)
}
