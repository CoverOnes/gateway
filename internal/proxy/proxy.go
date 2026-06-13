// Package proxy provides a reverse proxy registry backed by an allowlist route table.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/CoverOnes/gateway/internal/config"
	"github.com/CoverOnes/gateway/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

// plainResponseWriter wraps an http.ResponseWriter and deliberately does NOT
// implement http.CloseNotifier. This prevents httputil.ReverseProxy from
// calling CloseNotify() on gin's responseWriter (which panics when the
// underlying writer, e.g. httptest.ResponseRecorder, doesn't implement the interface).
type plainResponseWriter struct {
	http.ResponseWriter
}

// ctxKeyNormalizedPath is the context key used to pass the pre-computed,
// normalized upstream path from Forward (where the guard runs) to Rewrite
// (where the path is forwarded). This ensures guard and forwarder operate on
// the same cleaned path — fixing the CONVENTIONS §10 path-confusion finding.
type ctxKeyNormalizedPath struct{}

// sentinelNoForward is the host value set on req.Out.URL when the Rewrite
// closure detects a missing/empty normalized-path context key (S3 guard).
// Setting Host to "" causes the transport to fail the dial immediately, so
// the upstream server is never contacted — the ErrorHandler returns 502.
const sentinelNoForward = ""

// Registry maps service name to a pre-built ReverseProxy instance.
// Only services in the allowlist are proxied; unknown services get 404.
type Registry struct {
	proxies map[string]*httputil.ReverseProxy
}

// New builds a Registry from the given route table.
// One *httputil.ReverseProxy is created per allowlisted upstream at boot time.
func New(table config.RouteTable, proxyTimeoutSec int) (*Registry, error) {
	proxies := make(map[string]*httputil.ReverseProxy, len(table))

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: time.Duration(proxyTimeoutSec) * time.Second,
	}

	for svc, entry := range table {
		targetURL, err := url.Parse(entry.BaseURL)
		if err != nil {
			return nil, err
		}

		svcName := svc // capture for closure
		baseURL := targetURL

		rp := &httputil.ReverseProxy{
			// ModifyResponse enforces the gateway's security-header policy on every
			// upstream response. A compromised or misconfigured upstream that omits
			// or overrides these headers would otherwise be able to weaken the
			// client-side security posture. Re-setting them here ensures the gateway
			// always controls the final values regardless of what the upstream sends.
			//
			// CORS sole-authority: strip ALL upstream CORS headers so that only the
			// gateway's own CORS middleware (internal/platform/middleware/cors.go) sets
			// CORS headers on the final response. Without this strip, upstreams that run
			// their own CORS middleware (e.g. chat-gateway) produce duplicate
			// Access-Control-Allow-Origin values, which the Fetch spec treats as a CORS
			// failure — blocking the response body in the browser.
			// Vary is also stripped because the gateway's CORS middleware re-adds
			// "Vary: Origin" when the request Origin is allowed, ensuring the correct
			// single value survives.
			ModifyResponse: func(resp *http.Response) error {
				resp.Header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
				resp.Header.Set("X-Content-Type-Options", "nosniff")
				resp.Header.Set("X-Frame-Options", "DENY")
				resp.Header.Set("Referrer-Policy", "no-referrer")
				resp.Header.Set("Content-Security-Policy", "default-src 'none'")

				// Strip upstream CORS headers — gateway is the sole CORS authority.
				for _, h := range []string{
					"Access-Control-Allow-Origin",
					"Access-Control-Allow-Credentials",
					"Access-Control-Allow-Methods",
					"Access-Control-Allow-Headers",
					"Access-Control-Expose-Headers",
					"Access-Control-Max-Age",
					"Vary",
				} {
					resp.Header.Del(h)
				}

				return nil
			},
			Rewrite: func(req *httputil.ProxyRequest) {
				req.SetURL(baseURL)
				// Use the pre-computed normalized path stashed by Forward.
				// This guarantees the path forwarded to the upstream is IDENTICAL
				// to the path the internal-block guard validated — the guard and
				// the forwarder must operate on the same cleaned string.
				//
				// S3 — Missing context key guard.
				// If the normalized path is absent from context (e.g. a direct
				// ServeHTTP call bypassing Forward), refuse to forward the request
				// rather than silently falling back to whatever SetURL produced.
				// A caller that bypasses Forward skips the path-guard entirely —
				// forwarding the un-guarded path would reopen the bypass surface.
				//
				// To verifiably prevent upstream contact, set req.Out.URL.Host to
				// the empty string so the transport dial fails closed.  The proxy
				// ErrorHandler returns 502 BAD_GATEWAY, which is the correct
				// behavior: something went wrong in the gateway, not in the upstream.
				norm, ok := req.In.Context().Value(ctxKeyNormalizedPath{}).(string)
				if !ok || norm == "" {
					slog.Error(
						"proxy: normalized path missing from context; refusing to forward",
						"svc", svcName,
						"raw_path", req.In.URL.Path,
					)
					req.Out.URL.Host = sentinelNoForward
					req.Out.Body = http.NoBody

					return
				}

				req.Out.URL.Path = norm

				req.Out.URL.RawQuery = req.In.URL.RawQuery
				// Propagate X-Request-ID downstream.
				req.Out.Header.Set("X-Request-ID", req.In.Header.Get("X-Request-ID"))
			},
			Transport:     transport,
			FlushInterval: -1, // streaming support
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				// Detect request-body-too-large: http.MaxBytesReader fires this error
				// when the client sends a body that exceeds the gateway's limit.
				// Return 413 REQUEST_ENTITY_TOO_LARGE instead of 502 so the client
				// receives an actionable error code rather than a generic gateway error.
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					_, _ = w.Write([]byte(`{"error":{"code":"REQUEST_ENTITY_TOO_LARGE","message":"request body exceeds maximum allowed size"}}`))

					return
				}

				// Log the real error server-side ONLY; return generic envelope to client.
				slog.Error(
					"proxy upstream error",
					"svc", svcName,
					"err", err,
				)
				// Write error envelope directly (httputil.ErrorHandler uses http.ResponseWriter).
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"error":{"code":"BAD_GATEWAY","message":"upstream service unavailable"}}`))
			},
		}

		proxies[svc] = rp
	}

	return &Registry{proxies: proxies}, nil
}

// decodePathFully performs an idempotent URL-path decode loop: it repeatedly
// calls url.PathUnescape until the result is stable (unchanged) or an error
// occurs, then returns the fully-decoded string.
//
// Why idempotent loop: a single url.PathUnescape pass leaves n-level encoded
// sequences only partially decoded.  Example:
//
//	%252500internal
//	  → pass 1: %2500internal  (% was decoded, leaving %2500)
//	  → pass 2: %00internal    (still a literal %00 triplet)
//	  → pass 3: \x00internal   (NUL byte — now caught by raw-byte check)
//
// After the loop the result is the maximally-decoded form of the input.  Any
// control character (\x00, \r, \n) that survives to this form is a raw byte
// and is caught by the ContainsAny guard that follows.  No n-level encoding
// can smuggle a control character past a fully-decoded form.
//
// The loop is bounded because url.PathUnescape strictly shrinks the string on
// every successful pass (every %XX triplet it consumes shortens the string by
// at least one byte); once no %XX sequence remains the output equals the input
// and the loop terminates.
func decodePathFully(s string) string {
	for {
		next, err := url.PathUnescape(s)
		if err != nil || next == s {
			return s
		}

		s = next
	}
}

// upstreamPath returns the normalized path that will be forwarded to the upstream
// for the given public request path and service name, and whether the path is valid.
// It mirrors the Rewrite logic used by the ReverseProxy: strip the /api/<svc> prefix.
// The returned path is already percent-decoded and cleaned (no ".." segments, no "//").
//
// The boolean return value is false when the fully-decoded path contains characters
// that break path semantics (NUL byte, carriage-return, newline).  The idempotent
// decode loop (decodePathFully) ensures that n-level encoded control characters
// (%252500, %25252500, …) are fully unwrapped before the byte check — closing ALL
// n-level encoding bypass variants including triple and quad encoding.
// Callers MUST reject the request when the return value is false.
//
// UpstreamPathForSigning exposes the same transformation for use by the HMAC
// signer in the middleware layer: the signer MUST sign over the exact path the
// downstream receives (post-strip), not the raw gateway-side path.
func UpstreamPathForSigning(requestPath, svc string) (string, bool) {
	return upstreamPath(requestPath, svc)
}

func upstreamPath(requestPath, svc string) (string, bool) {
	// Strip /api/<svc> prefix.
	stripped := strings.TrimPrefix(requestPath, "/api/"+svc)
	if stripped == "" {
		stripped = "/"
	}

	// Idempotent decode loop: repeatedly url.PathUnescape until stable.
	// This collapses all layers of percent-encoding (%2500, %252500, …) into
	// their final decoded byte values before any guard runs.
	decoded := decodePathFully(stripped)

	// M1 — Null-byte / CRLF rejection.
	// After full decode, any \x00, \r, or \n is present as a raw byte.
	// Reject early (caller will return 400 INVALID_PATH) rather than forward.
	// This check now covers ALL n-level encoding variants: triple (%252500),
	// quad (%25252500), etc. — because decodePathFully unwraps them all.
	if strings.ContainsAny(decoded, "\x00\r\n") {
		return "", false
	}

	// path.Clean resolves "." and ".." segments, collapses "//" into "/", and
	// ensures the result starts with "/".
	return path.Clean(decoded), true
}

// containsInternalSegment reports whether the normalized upstream path would
// route to an /internal/ endpoint — i.e. any path segment in the cleaned path
// equals "internal" (case-insensitively).
//
// The comparison is case-insensitive on purpose: the guard's correctness must
// not depend on upstream routing being case-sensitive. A future upstream using
// a case-insensitive framework (Spring, Express with case-insensitive routing,
// etc.) would otherwise be reachable via /Internal/ or /INTERNAL/.
//
// Examples that return true:
//
//	/internal/v1/kyc/abc/status
//	/v1/foo/internal/bar
//	/Internal/v1/status  and  /INTERNAL/v1/status   (case-insensitive)
//	result of /api/kyc/foo/../internal/status (resolves to /internal/status)
//	result of /api/kyc/%2finternal/v1   (decoded to /internal/v1)
func containsInternalSegment(cleanedPath string) bool {
	// Split on "/" and check each segment.
	// path.Clean guarantees no leading "//" and no trailing "/" (unless root),
	// so splitting is safe.
	for _, seg := range strings.Split(cleanedPath, "/") {
		// M3 — Semicolon matrix-parameter bypass.
		// RFC 3986 §3.3 allows ";" in path segments as a path parameter delimiter
		// (matrix URIs). Some frameworks (Spring Matrix Variables, WebSphere) strip
		// the ";params" suffix before routing, so "/internal;foo" is routed the same
		// as "/internal". Strip everything from the first ";" before comparing so
		// "/internal;version=1" cannot bypass the guard.
		seg, _, _ = strings.Cut(seg, ";")

		// M2 — Trailing-dot bypass.
		// path.Clean("/internal./x") keeps "internal." verbatim; some upstreams
		// (e.g. IIS, Tomcat, nginx on Windows) strip trailing dots and route
		// "internal." to the /internal/* handler.  Strip all trailing dots before
		// the case-insensitive comparison so "internal.", "internal..", etc. are
		// treated identically to "internal".
		normalised := strings.TrimRight(seg, ".")
		if strings.EqualFold(normalised, "internal") {
			return true
		}
	}

	return false
}

// Forward proxies the request to the named upstream service.
// Returns false and writes a 404 response if the service is not in the allowlist.
//
// Defense-in-depth: if the resolved upstream path contains an /internal/ segment
// (after percent-decoding and path-cleaning), the request is refused with 404 so
// that S2S-only endpoints are never reachable through the public gateway regardless
// of how the upstream routes them.
//
// Path normalization: the normalized (cleaned) upstream path is stashed in the
// request context so that Rewrite forwards the SAME path the guard validated —
// preventing guard-bypass via dot-dot/double-slash/percent-encoding divergence.
func (r *Registry) Forward(c *gin.Context, svc string) {
	rp, ok := r.proxies[svc]
	if !ok {
		httpx.ErrCode(c, http.StatusNotFound, "SERVICE_NOT_FOUND", "service not found in allowlist")

		return
	}

	// Compute the normalized upstream path once. This is the canonical form
	// that both the guard below and Rewrite above must agree on.
	//
	// upstreamPath also validates that the decoded path does not contain
	// characters that break path semantics (NUL, CR, LF — see M1 fix).
	normalized, valid := upstreamPath(c.Request.URL.Path, svc)
	if !valid {
		slog.Warn(
			"proxy: rejected request with invalid path characters (NUL/CR/LF)",
			"svc", svc,
			"raw_path", c.Request.URL.Path,
		)
		httpx.ErrCode(c, http.StatusBadRequest, "INVALID_PATH", "invalid path")

		return
	}

	// Block any path whose normalized upstream path contains an "internal" segment.
	// Return 404 (not 403) to avoid revealing that the endpoint exists.
	if containsInternalSegment(normalized) {
		slog.Warn(
			"proxy: blocked request targeting internal path",
			"svc", svc,
			"raw_path", c.Request.URL.Path,
			"normalized_path", normalized,
		)
		httpx.ErrCode(c, http.StatusNotFound, "NOT_FOUND", "not found")

		return
	}

	// Stash the normalized path in the request context so Rewrite picks it up.
	// This closes the guard-vs-forwarder split: Rewrite uses the cleaned path
	// the guard just validated rather than re-stripping the raw (un-cleaned) path.
	c.Request = c.Request.WithContext(
		context.WithValue(c.Request.Context(), ctxKeyNormalizedPath{}, normalized),
	)

	// Wrap c.Writer in plainResponseWriter to prevent httputil.ReverseProxy from
	// type-asserting to http.CloseNotifier (gin's responseWriter panics when the
	// underlying writer doesn't implement CloseNotify, e.g. httptest.ResponseRecorder).
	rp.ServeHTTP(&plainResponseWriter{ResponseWriter: c.Writer}, c.Request)
}
