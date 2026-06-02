// Package httpx provides shared HTTP response helpers for the gateway service.
package httpx

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// OK sends a 200 JSON response with data envelope.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// Created sends a 201 JSON response with data envelope.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, gin.H{"data": data})
}

// NoContent sends a 204 response with no body.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}
