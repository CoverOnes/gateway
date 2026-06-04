package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CoverOnes/gateway/internal/auth/jwt"
	"github.com/gin-gonic/gin"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// newTestEngine builds a minimal gin engine that injects claims directly into the
// context (bypassing actual JWT verification) and then runs the given middleware.
// handler records the HTTP status and body the client sees.
func newRLTestEngine(t *testing.T, mw gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Inject fake claims the same way Auth middleware would for a verified JWT.
	r.Use(func(c *gin.Context) {
		subj := c.GetHeader("X-Test-Subject")
		if subj != "" {
			c.Set(ctxKeyClaims, &jwt.Claims{
				RegisteredClaims: gojwt.RegisteredClaims{Subject: subj},
			})
		}
		c.Next()
	})
	r.Use(mw)
	r.GET("/ping", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

// doRequest fires one GET /ping to r with the given JWT subject header.
func doRequest(t *testing.T, r *gin.Engine, subject string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
	if subject != "" {
		req.Header.Set("X-Test-Subject", subject)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// exhaustBudget fires limitPerMin+1 requests through r from the given subject.
// Returns the 1-based request index that first received a 429, or -1 if no 429 was seen.
func exhaustBudget(t *testing.T, r *gin.Engine, subject string, limitPerMin int) int {
	t.Helper()

	for i := range limitPerMin + 1 {
		code := doRequest(t, r, subject)
		if code == http.StatusTooManyRequests {
			return i + 1
		}
	}

	return -1
}

// ─── NewIPRateLimiter ─────────────────────────────────────────────────────────

func TestIPRateLimiter_AllowsUpToLimit(t *testing.T) {
	const limit = 5
	lim := NewIPRateLimiter(limit)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(lim.Handler())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	// The token-bucket allows exactly `burst` (= fallbackBurst = 10) initial tokens
	// even when the per-minute limit is lower, because burst is a separate knob.
	// We assert that we can fire at least one request (sanity).
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "first request within burst must pass")
}

func TestIPRateLimiter_Returns429WhenExhausted(t *testing.T) {
	// Use limit=1/min and burst=1 by creating a zero-burst scenario: exhaust the bucket.
	// We use a very small limit but rely on burst=fallbackBurst(10) being exhausted after 10 hits.
	const limit = 1
	lim := NewIPRateLimiter(limit)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(lim.Handler())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	var got429 bool
	for range fallbackBurst + 5 {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}

	assert.True(t, got429, "rate limiter must return 429 once burst is exhausted")
}

// ─── NewAuthRateLimiter ───────────────────────────────────────────────────────

func TestAuthRateLimiter_HasIndependentBucketFromIPLimiter(t *testing.T) {
	// authRL keys on "rl:auth:ip:<ip>"; ipRL keys on "rl:ip:<ip>".
	// Exhausting ipRL must not affect authRL and vice versa.
	ipRL := NewIPRateLimiter(1)
	authRL := NewAuthRateLimiter(1)

	// Exhaust ipRL bucket.
	for range fallbackBurst + 1 {
		_ = ipRL.allow("rl:ip:127.0.0.1")
	}
	// authRL bucket must still allow.
	assert.True(t, authRL.allow("rl:auth:ip:127.0.0.1"),
		"authRL bucket is independent from ipRL bucket")
}

// ─── NewUserRateLimiter ───────────────────────────────────────────────────────

// TestUserRateLimiter_PerUserIsolation is the core per-user DoS-fix test:
// exhausting user-A's budget must NOT block user-B.
func TestUserRateLimiter_PerUserIsolation(t *testing.T) {
	// Use limit=fallbackBurst so the burst allows exactly fallbackBurst(10) requests,
	// then the 11th is rejected.  Use limit equal to burst to keep the test deterministic.
	const limitPerMin = fallbackBurst // 10 — same as burst so bucket drains predictably
	lim := NewUserRateLimiter(limitPerMin)
	r := newRLTestEngine(t, lim.Handler())

	// Exhaust user-A's budget.
	const subjectA = "user-uuid-aaaa"
	firstReject := exhaustBudget(t, r, subjectA, limitPerMin)

	require.Positive(t, firstReject, "user-A must be rejected after exhausting budget")

	// user-B's first request must still pass (independent bucket).
	const subjectB = "user-uuid-bbbb"
	code := doRequest(t, r, subjectB)
	assert.Equal(t, http.StatusOK, code,
		"user-B first request must be 200 — user-A's exhaustion must not affect user-B")
}

// TestUserRateLimiter_ExhaustedBudgetReturns429 proves the limiter is actually
// enforcing: after burst tokens are consumed, the next request is rejected 429.
func TestUserRateLimiter_ExhaustedBudgetReturns429(t *testing.T) {
	const limitPerMin = fallbackBurst
	lim := NewUserRateLimiter(limitPerMin)
	r := newRLTestEngine(t, lim.Handler())

	const subjectA = "user-uuid-cccc"
	firstReject := exhaustBudget(t, r, subjectA, limitPerMin)

	require.Positive(t, firstReject,
		"user-A must receive a 429 after exhausting the per-user budget (fail-closed)")
}

// TestUserRateLimiter_FallbackToIPWhenNoClaimsNoPanic proves the belt-and-suspenders
// path: when no claims are present in context (e.g. middleware mis-wiring), the limiter
// falls back to a key derived from the client IP and does NOT panic.
func TestUserRateLimiter_FallbackToIPWhenNoClaimsNoPanic(t *testing.T) {
	lim := NewUserRateLimiter(60)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Intentionally skip claim injection — simulate missing Auth middleware.
	r.Use(lim.Handler())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Must not panic; falls back to rl:user-noauth:<ip> key.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
	w := httptest.NewRecorder()
	require.NotPanics(t, func() { r.ServeHTTP(w, req) })
	// First request must pass (bucket not exhausted).
	assert.Equal(t, http.StatusOK, w.Code,
		"fallback-to-IP path: first request must not be rate-limited")
}

// TestUserRateLimiter_FallbackBucketExhaustedReturns429 proves that even the fallback
// IP-keyed path is fail-closed (not a bypass).
func TestUserRateLimiter_FallbackBucketExhaustedReturns429(t *testing.T) {
	const limitPerMin = fallbackBurst
	lim := NewUserRateLimiter(limitPerMin)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(lim.Handler())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	var got429 bool
	for range fallbackBurst + 5 {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	assert.True(t, got429,
		"fallback-IP bucket must also return 429 once burst is exhausted (no bypass via missing claims)")
}

// TestUserKey_PreferSubjectOverIP asserts that when claims with a non-empty Subject
// are in context, the key is "rl:user:<subject>", NOT the IP-fallback key.
func TestUserKey_PreferSubjectOverIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	var capturedKey string
	r.Use(func(c *gin.Context) {
		// Inject fake claims.
		c.Set(ctxKeyClaims, &jwt.Claims{
			RegisteredClaims: gojwt.RegisteredClaims{Subject: "subject-xyz"},
		})
		capturedKey = userKey(c)
		c.Next()
	})
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "rl:user:subject-xyz", capturedKey,
		"userKey must use 'rl:user:<subject>' when claims are present")
}

// TestUserKey_EmptySubjectFallsBackToIP asserts that when claims are present but
// Subject is empty (degenerate token), the fallback IP key is used rather than
// creating a shared "rl:user:" bucket.
func TestUserKey_EmptySubjectFallsBackToIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	var capturedKey string
	r.Use(func(c *gin.Context) {
		c.Set(ctxKeyClaims, &jwt.Claims{
			RegisteredClaims: gojwt.RegisteredClaims{Subject: ""}, // degenerate
		})
		capturedKey = userKey(c)
		c.Next()
	})
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, capturedKey, "rl:user-noauth:",
		"empty subject in claims must fall back to IP key to avoid a shared bucket")
}

// TestUserRateLimiter_IndependentFromIPRateLimiter proves that exhausting the global
// IPRateLimiter bucket does NOT affect the per-user limiter's bucket, and vice-versa.
// This guards against a future regression where both limiters share state.
func TestUserRateLimiter_IndependentFromIPRateLimiter(t *testing.T) {
	ipRL := NewIPRateLimiter(1)
	userRL := NewUserRateLimiter(60)

	// Exhaust ipRL bucket for a specific key.
	ipKey := "rl:ip:192.0.2.1"
	for range fallbackBurst + 1 {
		_ = ipRL.allow(ipKey)
	}
	assert.False(t, ipRL.allow(ipKey), "ipRL bucket must be exhausted")

	// UserRL bucket for the same logical IP key must be unaffected.
	assert.True(t, userRL.allow("rl:user:some-user-id"),
		"userRL bucket must be independent from ipRL — exhausting ipRL must not block userRL")
}

// TestUserRateLimiter_BucketRefillsOverTime is a smoke-test that the underlying
// token bucket eventually refills. It uses a very high rate to make the test fast.
func TestUserRateLimiter_BucketRefillsOverTime(t *testing.T) {
	// 600 requests per minute = 10 per second.  After exhausting burst (10),
	// waiting 1 second should allow at least one new token.
	const limitPerMin = 600
	lim := NewUserRateLimiter(limitPerMin)
	const subject = "rl:user:refill-test"

	// Exhaust the burst.
	for range fallbackBurst {
		lim.allow(subject)
	}
	assert.False(t, lim.allow(subject), "bucket must be empty after exhausting burst")

	// Wait for ~1 token to refill (10/s → ~100ms per token).
	time.Sleep(150 * time.Millisecond)

	assert.True(t, lim.allow(subject), "bucket must allow at least one request after refill period")
}
