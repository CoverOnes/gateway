// Package proxy provides a reverse proxy registry backed by an allowlist route table.
package proxy

import (
	"context"
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
			Rewrite: func(req *httputil.ProxyRequest) {
				req.SetURL(baseURL)
				// Use the pre-computed normalized path stashed by Forward.
				// This guarantees the path forwarded to the upstream is IDENTICAL
				// to the path the internal-block guard validated — the guard and
				// the forwarder must operate on the same cleaned string.
				if norm, ok := req.In.Context().Value(ctxKeyNormalizedPath{}).(string); ok && norm != "" {
					req.Out.URL.Path = norm
				}

				req.Out.URL.RawQuery = req.In.URL.RawQuery
				// Propagate X-Request-ID downstream.
				req.Out.Header.Set("X-Request-ID", req.In.Header.Get("X-Request-ID"))
			},
			Transport:     transport,
			FlushInterval: -1, // streaming support
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
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

// upstreamPath returns the normalized path that will be forwarded to the upstream
// for the given public request path and service name.
// It mirrors the Rewrite logic used by the ReverseProxy: strip the /api/<svc> prefix.
// The returned path is already percent-decoded and cleaned (no ".." segments, no "//").
func upstreamPath(requestPath, svc string) string {
	// Strip /api/<svc> prefix.
	stripped := strings.TrimPrefix(requestPath, "/api/"+svc)
	if stripped == "" {
		stripped = "/"
	}

	// Percent-decode the path so that %2f → / and %2e%2e → .. are visible before
	// the path-traversal check.  url.PathUnescape is the correct decoder here:
	// it replaces every %XX sequence with its byte value but does not error on
	// plain slashes (unlike url.QueryUnescape which treats '+' as a space).
	decoded, err := url.PathUnescape(stripped)
	if err != nil {
		// Malformed percent-encoding: treat as the raw (potentially still
		// percent-encoded) path so that path.Clean can normalise it.
		decoded = stripped
	}

	// path.Clean resolves "." and ".." segments, collapses "//" into "/", and
	// ensures the result starts with "/".
	return path.Clean(decoded)
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
		if strings.EqualFold(seg, "internal") {
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
	normalized := upstreamPath(c.Request.URL.Path, svc)

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
