package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/CoverOnes/gateway/internal/platform/httpx"
	"github.com/gin-gonic/gin"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

// userFallbackLRUCap is the maximum number of unique user subjects tracked by the
// in-process per-user limiter. Bounding by LRU prevents memory exhaustion under
// high account-rotation attacks.
const userFallbackLRUCap = 100_000

// fallbackBurst is the token-bucket burst for the in-process IP-keyed limiters
// (IPRateLimiter and AuthRateLimiter). It does NOT apply to UserRateLimiter,
// which uses a separately configurable burst via NewUserRateLimiter.
// Set conservatively: 10 requests per second per IP.
const fallbackBurst = 10

// fallbackLRUCap is the maximum number of unique keys tracked by the in-process
// limiter. When the cap is reached, the least-recently-used entry is evicted,
// bounding memory to O(cap × sizeof(*rate.Limiter)) regardless of how many
// unique source IPs an attacker rotates through (memory-DoS safe).
const fallbackLRUCap = 100_000

// IPRateLimiter is an in-process token-bucket rate limiter keyed by client IP.
// The bucket map is bounded by an LRU cache so that IP rotation cannot exhaust memory.
// This is the walking-skeleton implementation; a Redis sliding-window is a deferred follow-up.
type IPRateLimiter struct {
	mu      sync.Mutex
	buckets *lru.Cache[string, *rate.Limiter]
	r       rate.Limit
	burst   int
	keyFunc func(c *gin.Context) string
}

// NewIPRateLimiter builds a per-IP limiter with the given per-minute budget.
func NewIPRateLimiter(limitPerMin int) *IPRateLimiter {
	r := rate.Limit(float64(limitPerMin) / 60.0)

	cache, err := lru.New[string, *rate.Limiter](fallbackLRUCap)
	if err != nil {
		// lru.New only errors when cap <= 0, which cannot happen here.
		panic(fmt.Sprintf("IPRateLimiter: unexpected lru.New error: %v", err))
	}

	return &IPRateLimiter{
		buckets: cache,
		r:       r,
		burst:   fallbackBurst,
		keyFunc: func(c *gin.Context) string {
			return fmt.Sprintf("rl:ip:%s", c.ClientIP())
		},
	}
}

// NewAuthRateLimiter builds a tighter per-IP limiter for auth routes.
func NewAuthRateLimiter(limitPerMin int) *IPRateLimiter {
	r := rate.Limit(float64(limitPerMin) / 60.0)

	cache, err := lru.New[string, *rate.Limiter](fallbackLRUCap)
	if err != nil {
		panic(fmt.Sprintf("AuthRateLimiter: unexpected lru.New error: %v", err))
	}

	return &IPRateLimiter{
		buckets: cache,
		r:       r,
		burst:   fallbackBurst,
		keyFunc: func(c *gin.Context) string {
			return fmt.Sprintf("rl:auth:ip:%s", c.ClientIP())
		},
	}
}

func (l *IPRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	lim, ok := l.buckets.Get(key)
	if !ok {
		lim = rate.NewLimiter(l.r, l.burst)
		l.buckets.Add(key, lim)
	}

	return lim.Allow()
}

// Handler returns the Gin middleware function.
// Fail-closed: over-limit always returns 429 RATE_LIMITED.
func (l *IPRateLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := l.keyFunc(c)
		if !l.allow(key) {
			c.Abort()
			httpx.ErrCode(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")

			return
		}

		c.Next()
	}
}

// RateLimitWindow is retained for constructing window-aware limiters in tests.
const RateLimitWindow = time.Minute

// UserRateLimiter is a per-authenticated-user in-process token-bucket rate limiter.
// Key is derived from the JWT subject (claims.Subject) set by the Auth middleware.
// When no claims are present in context — which cannot happen on properly-wired routes
// since Auth always runs before this middleware, but is defended here belt-and-suspenders —
// the key falls back to "rl:user-noauth:<ip>" to avoid a nil-key panic.
//
// Multi-pod caveat: this is an in-process limiter. Each pod maintains its own bucket,
// so the effective per-user limit across N pods is N×limitPerMin. A Redis sliding-window
// implementation should be added when accurate cross-pod enforcement is required.
// Document this to make the trade-off visible to operators.
type UserRateLimiter struct {
	mu      sync.Mutex
	buckets *lru.Cache[string, *rate.Limiter]
	r       rate.Limit
	burst   int
}

// NewUserRateLimiter builds a per-authenticated-user rate limiter with the given
// per-minute budget and burst size. The limiter is keyed on JWT subject (user UUID).
// burst must be > 0; caller is responsible for validating this at config load time.
func NewUserRateLimiter(limitPerMin, burst int) *UserRateLimiter {
	r := rate.Limit(float64(limitPerMin) / 60.0)

	cache, err := lru.New[string, *rate.Limiter](userFallbackLRUCap)
	if err != nil {
		// lru.New only errors when cap <= 0, which cannot happen here.
		panic(fmt.Sprintf("UserRateLimiter: unexpected lru.New error: %v", err))
	}

	return &UserRateLimiter{
		buckets: cache,
		r:       r,
		burst:   burst,
	}
}

func (l *UserRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	lim, ok := l.buckets.Get(key)
	if !ok {
		lim = rate.NewLimiter(l.r, l.burst)
		l.buckets.Add(key, lim)
	}

	return lim.Allow()
}

// userKey derives the rate-limit bucket key for the current request.
// Primary key: "rl:user:<claims.Subject>" (authenticated — the normal path).
// Fallback key: "rl:user-noauth:<clientIP>" (no claims in ctx — belt-and-suspenders;
// authMW has already rejected unauthenticated requests before this middleware runs).
func userKey(c *gin.Context) string {
	if claims, ok := ClaimsFromCtx(c); ok && claims.Subject != "" {
		return "rl:user:" + claims.Subject
	}

	return "rl:user-noauth:" + c.ClientIP()
}

// Handler returns the Gin middleware function.
// Fail-closed: over-limit always returns 429 RATE_LIMITED.
func (l *UserRateLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := userKey(c)
		if !l.allow(key) {
			c.Abort()
			httpx.ErrCode(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")

			return
		}

		c.Next()
	}
}
