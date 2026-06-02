// Package logger provides a slog-based JSON logger constructor for the gateway service.
package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	userIDKey    contextKey = "user_id"
)

// New creates a JSON slog logger writing to stdout at the given level.
func New(level string) *slog.Logger {
	var lvl slog.Level

	switch strings.ToUpper(level) {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "WARN":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})

	return slog.New(h)
}

// WithRequestID returns a context carrying the request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// WithUserID returns a context carrying the authenticated user ID.
func WithUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// FromContext extracts slog attrs from context for structured logging.
func FromContext(ctx context.Context) []any {
	var attrs []any

	if rid, ok := ctx.Value(requestIDKey).(string); ok && rid != "" {
		attrs = append(attrs, slog.String("request_id", rid))
	}

	if uid, ok := ctx.Value(userIDKey).(string); ok && uid != "" {
		attrs = append(attrs, slog.String("user_id", uid))
	}

	return attrs
}
