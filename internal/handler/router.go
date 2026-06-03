package handler

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/CoverOnes/gateway/internal/auth/jwks"
	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/CoverOnes/gateway/internal/config"
	"github.com/CoverOnes/gateway/internal/platform/health"
	"github.com/CoverOnes/gateway/internal/platform/middleware"
	"github.com/CoverOnes/gateway/internal/proxy"
	"github.com/gin-gonic/gin"
)

// RouterConfig holds all handler-level dependencies.
type RouterConfig struct {
	Verifier            *jwt.Verifier
	JWKSCache           *jwks.Cache
	RouteTable          config.RouteTable
	ProxyTimeout        int
	RateLimitPerMin     int      // GATEWAY_RATE_LIMIT_PER_MIN; 0 → default 60
	AuthRateLimitPerMin int      // GATEWAY_AUTH_RATE_LIMIT_PER_MIN; 0 → default 20
	CORSOrigins         []string // GATEWAY_CORS_ORIGINS; nil/empty disables CORS headers
}

// rateLimitOrDefault returns v if > 0, otherwise fallback.
func rateLimitOrDefault(v, fallback int) int {
	if v > 0 {
		return v
	}

	return fallback
}

// NewRouter builds and returns the configured Gin engine.
// Route chain order per CONVENTIONS.md §9:
// Recover -> RequestID -> SecurityHeaders -> StripIdentityHeaders -> accessLogger
// -> [health+jwks pre-ratelimit]
// -> RateLimit -> public passthrough groups -> protected proxy groups (Auth -> InjectIdentity -> Forward)
//
// Returns an error if the proxy registry cannot be built (invalid route table).
// Callers should handle the error and fail fast at boot rather than panic.
func NewRouter(cfg RouterConfig) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.SetTrustedProxies(nil) //nolint:errcheck // nil proxy list disables proxy trust; gin docs confirm error is always nil for nil argument

	// CORS must be first — preflight OPTIONS must be handled before any other middleware
	// (rate limiter, auth, etc.) can reject the request.
	if len(cfg.CORSOrigins) > 0 {
		r.Use(middleware.CORS(cfg.CORSOrigins))
	}

	// Global middleware chain.
	r.Use(middleware.Recover())
	r.Use(middleware.RequestID())
	r.Use(middleware.SecurityHeaders())
	// StripIdentityHeaders runs GLOBALLY (before routing) so every route —
	// including public ones — cannot be spoofed by a client-supplied identity header.
	r.Use(middleware.StripIdentityHeaders())
	r.Use(accessLogger())

	// Health endpoints — registered BEFORE rate limiter so probes are never rate-limited.
	healthHandler := health.NewHandler(cfg.JWKSCache)
	r.GET("/healthz", healthHandler.Liveness)
	r.GET("/readyz", healthHandler.Readiness)

	// Build proxy registry from route table.
	registry, err := proxy.New(cfg.RouteTable, cfg.ProxyTimeout)
	if err != nil {
		return nil, fmt.Errorf("build proxy registry: %w", err)
	}

	proxyH := NewProxyHandler(registry)

	// Rate limiter — applied to all routes below.
	// Values come from config (GATEWAY_RATE_LIMIT_PER_MIN / GATEWAY_AUTH_RATE_LIMIT_PER_MIN).
	ipRL := middleware.NewIPRateLimiter(rateLimitOrDefault(cfg.RateLimitPerMin, 60))
	r.Use(ipRL.Handler())

	// Public passthrough: /jwks — forward to user upstream, no auth.
	// JWKS is public key material, cache-friendly, no rate limit needed.
	r.GET("/jwks", func(c *gin.Context) {
		registry.Forward(c, "user")
	})

	// Public auth routes — no JWT, but NoCache + tighter rate limit.
	authRL := middleware.NewAuthRateLimiter(rateLimitOrDefault(cfg.AuthRateLimitPerMin, 20))
	authGroup := r.Group("/v1/auth")
	authGroup.Use(middleware.NoCache())
	authGroup.Use(authRL.Handler())
	authGroup.POST("/register", func(c *gin.Context) {
		registry.Forward(c, "user")
	})
	authGroup.POST("/login", func(c *gin.Context) {
		registry.Forward(c, "user")
	})
	authGroup.POST("/refresh", func(c *gin.Context) {
		registry.Forward(c, "user")
	})

	// Logout requires a valid access token — protected.
	authMW := middleware.Auth(cfg.Verifier)
	authGroup.POST(
		"/logout",
		authMW,
		middleware.InjectIdentity(),
		func(c *gin.Context) {
			registry.Forward(c, "user")
		},
	)

	// Protected proxy routes — Auth + InjectIdentity required.
	// /api/:svc/* pattern with allowlist-only forwarding.
	api := r.Group("/api/:svc")
	api.Use(authMW)
	api.Use(middleware.InjectIdentity())
	api.Any("/*proxyPath", proxyH.Forward)

	return r, nil
}

// accessLogger returns a minimal slog-based access-log middleware.
// Health probe paths (/healthz, /readyz) are skipped to avoid noise in production logs.
func accessLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		// Skip probe endpoints — they are high-frequency, low-value log entries.
		if path == "/healthz" || path == "/readyz" {
			c.Next()

			return
		}

		start := time.Now()
		c.Next()
		slog.Info(
			"http",
			"method", c.Request.Method,
			"path", path,
			"status", c.Writer.Status(),
			"latency_ms", time.Since(start).Milliseconds(),
			"request_id", c.GetString("request_id"),
		)
	}
}

// NewRouterFromConfig builds a RouterConfig from a full app config and a JWKS cache.
// This is the entrypoint used by cmd/server/main.go.
func NewRouterFromConfig(appCfg *config.Config, cache *jwks.Cache) (*gin.Engine, error) {
	table, err := config.ParseRouteTable(appCfg)
	if err != nil {
		return nil, err
	}

	verifier := jwt.NewVerifier(cache, appCfg.JWTIssuer, appCfg.JWTAudience, appCfg.JWTLeewaySec)

	var corsOrigins []string
	if appCfg.CORSOrigins != "" {
		for _, o := range strings.Split(appCfg.CORSOrigins, ",") {
			s := strings.TrimSpace(o)
			if s == "" {
				continue
			}
			// Reject wildcard / null: combining "*"/"null" with credentials is CWE-942.
			if s == "*" || strings.EqualFold(s, "null") {
				slog.Warn("cors: ignoring unsafe origin entry (wildcard/null not allowed with credentials)", "entry", s)
				continue
			}
			corsOrigins = append(corsOrigins, s)
		}
		if len(corsOrigins) > 0 {
			slog.Info("cors: allowlist configured", "origins", corsOrigins)
		}
	}

	r, err := NewRouter(RouterConfig{
		Verifier:            verifier,
		JWKSCache:           cache,
		RouteTable:          table,
		ProxyTimeout:        appCfg.ProxyTimeoutSec,
		RateLimitPerMin:     appCfg.RateLimitPerMin,
		AuthRateLimitPerMin: appCfg.AuthRateLimitPerMin,
		CORSOrigins:         corsOrigins,
	})
	if err != nil {
		return nil, err
	}

	return r, nil
}
