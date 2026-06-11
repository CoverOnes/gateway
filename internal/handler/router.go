package handler

import (
	"fmt"
	"log/slog"
	"net/http"
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

// bodyLimitAPI is the maximum request body size for /api/* proxy routes (10 MiB).
// Upstream services can enforce tighter limits per-endpoint; this guards the gateway.
const bodyLimitAPI = 10 << 20 // 10 MiB

// bodyLimitAuth is the maximum request body size for /v1/auth/* routes (64 KiB).
// Auth payloads (login, register, refresh tokens) are always small JSON objects; a 64 KiB
// limit prevents body-buffering DoS on the gateway before the upstream is ever reached.
const bodyLimitAuth = 64 << 10 // 64 KiB

// RouterConfig holds all handler-level dependencies.
type RouterConfig struct {
	Verifier            *jwt.Verifier
	JWKSCache           *jwks.Cache
	RouteTable          config.RouteTable
	ProxyTimeout        int
	RateLimitPerMin     int      // GATEWAY_RATE_LIMIT_PER_MIN; 0 → default 60
	AuthRateLimitPerMin int      // GATEWAY_AUTH_RATE_LIMIT_PER_MIN; 0 → default 20
	UserRateLimitPerMin int      // GATEWAY_USER_RATE_LIMIT_PER_MIN; 0 → default 300
	UserRateLimitBurst  int      // GATEWAY_USER_RATE_LIMIT_BURST; 0 → default 30
	CORSOrigins         []string // GATEWAY_CORS_ORIGINS; nil/empty disables CORS headers
	// HMACSecret signs the gateway-origin identity tuple (CONVENTIONS §24).
	// Empty → signing disabled (development only; non-dev config fails fast).
	HMACSecret []byte
	// TrustedProxyCIDRs is the parsed list from GATEWAY_TRUSTED_PROXY_CIDR.
	// When non-nil, Gin calls SetTrustedProxies with these CIDRs so that
	// ClientIP reads the real client IP from X-Forwarded-For.
	// nil (default) → SetTrustedProxies(nil), all proxy trust disabled.
	TrustedProxyCIDRs []string
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
// CORS (first — preflight must not be blocked by later middleware)
// -> Recover -> RequestID -> SecurityHeaders -> StripIdentityHeaders -> accessLogger
// -> [health /healthz /readyz — registered before ipRL, never rate-limited]
// -> GlobalIPRateLimit
// -> /jwks + authGroup (register, login, refresh, verify-email, resend-verification) with authRL
// -> /v1/auth/logout (NOT in authGroup — uses NoCache + authMW + userRL only, no authRL)
// -> protected proxy groups /api/:svc (Auth -> PerUserRateLimit(claims.Subject) -> InjectIdentity -> Forward)
//
// Returns an error if the proxy registry cannot be built (invalid route table).
// Callers should handle the error and fail fast at boot rather than panic.
//
// cfg is taken by pointer: RouterConfig is a heavy struct (read once at boot).
func NewRouter(cfg *RouterConfig) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	// Trusted proxy configuration — determines how ClientIP resolves the real client IP.
	// When TrustedProxyCIDRs is set (production/staging behind a LB), Gin reads the real
	// client IP from X-Forwarded-For so that per-IP rate limiting keys on the actual client
	// instead of the shared LB egress IP.
	// When nil (development / unset), all proxy trust is disabled: ClientIP returns the
	// direct connection IP — safe for direct internet-facing deployments without an LB.
	if len(cfg.TrustedProxyCIDRs) > 0 {
		if err := r.SetTrustedProxies(cfg.TrustedProxyCIDRs); err != nil {
			return nil, fmt.Errorf("set trusted proxies: %w", err)
		}
	} else {
		r.SetTrustedProxies(nil) //nolint:errcheck // nil proxy list disables proxy trust; gin docs confirm error is always nil for nil argument
	}

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

	// Public auth routes — no JWT, but NoCache + tighter rate limit + tight body limit.
	authRL := middleware.NewAuthRateLimiter(rateLimitOrDefault(cfg.AuthRateLimitPerMin, 20))
	authGroup := r.Group("/v1/auth")
	authGroup.Use(middleware.NoCache())
	authGroup.Use(authRL.Handler())
	authGroup.Use(bodyLimitMiddleware(bodyLimitAuth))
	authGroup.POST("/register", func(c *gin.Context) {
		registry.Forward(c, "user")
	})
	authGroup.POST("/login", func(c *gin.Context) {
		registry.Forward(c, "user")
	})
	authGroup.POST("/refresh", func(c *gin.Context) {
		registry.Forward(c, "user")
	})
	// Email verification — public (the user is not logged in yet), NoCache + authRL.
	authGroup.POST("/verify-email", func(c *gin.Context) {
		registry.Forward(c, "user")
	})
	authGroup.POST("/resend-verification", func(c *gin.Context) {
		registry.Forward(c, "user")
	})

	// Per-user rate limiter: keyed on JWT subject (user UUID).
	// Placed AFTER Auth (which validates the JWT and injects claims) so the key is always
	// the authenticated user identity, never an attacker-supplied value.
	// Placed BEFORE InjectIdentity so a rate-limited request is rejected before downstream
	// services are involved at all.
	authMW := middleware.Auth(cfg.Verifier)
	userRL := middleware.NewUserRateLimiter(
		rateLimitOrDefault(cfg.UserRateLimitPerMin, 300),
		rateLimitOrDefault(cfg.UserRateLimitBurst, 30),
	)

	// Logout requires a valid access token and is intentionally NOT inside authGroup so it
	// does NOT inherit the IP-keyed authRL limiter. Behind shared NAT, 20+ users logging
	// out concurrently would otherwise be blocked from invalidating their sessions.
	// Logout is keyed on JWT subject (via userRL) — not on IP — so per-user enforcement
	// still applies without punishing legitimate users sharing an egress IP.
	r.POST(
		"/v1/auth/logout",
		middleware.NoCache(),
		bodyLimitMiddleware(bodyLimitAuth),
		authMW,
		userRL.Handler(),
		middleware.InjectIdentity(cfg.HMACSecret),
		func(c *gin.Context) {
			registry.Forward(c, "user")
		},
	)

	// Protected proxy routes — Auth + PerUserRateLimit + InjectIdentity required.
	// /api/:svc/* pattern with allowlist-only forwarding.
	api := r.Group("/api/:svc")
	api.Use(bodyLimitMiddleware(bodyLimitAPI))
	api.Use(authMW)
	api.Use(userRL.Handler())
	api.Use(middleware.InjectIdentity(cfg.HMACSecret))
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

// bodyLimitMiddleware returns a Gin middleware that caps the request body to maxBytes.
// When the body exceeds the limit, http.MaxBytesReader causes the downstream proxy
// ErrorHandler to detect a *http.MaxBytesError and return 413 REQUEST_ENTITY_TOO_LARGE.
// This prevents body-buffering DoS on both auth and proxy routes.
func bodyLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}

		c.Next()
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

	// Parse trusted proxy CIDRs — validated at boot by config.Load(), safe to ignore error here.
	trustedProxyCIDRs, err := appCfg.ValidateTrustedProxyCIDRs()
	if err != nil {
		return nil, fmt.Errorf("trusted proxy CIDRs: %w", err)
	}

	if len(trustedProxyCIDRs) > 0 {
		slog.Info("trusted proxy CIDRs configured", "cidrs", trustedProxyCIDRs)
	}

	r, err := NewRouter(&RouterConfig{
		Verifier:            verifier,
		JWKSCache:           cache,
		RouteTable:          table,
		ProxyTimeout:        appCfg.ProxyTimeoutSec,
		RateLimitPerMin:     appCfg.RateLimitPerMin,
		AuthRateLimitPerMin: appCfg.AuthRateLimitPerMin,
		UserRateLimitPerMin: appCfg.UserRateLimitPerMin,
		UserRateLimitBurst:  appCfg.UserRateLimitBurst,
		CORSOrigins:         corsOrigins,
		HMACSecret:          []byte(appCfg.HMACSecret),
		TrustedProxyCIDRs:   trustedProxyCIDRs,
	})
	if err != nil {
		return nil, err
	}

	return r, nil
}
