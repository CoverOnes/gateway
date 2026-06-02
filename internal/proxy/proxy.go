// Package proxy provides a reverse proxy registry backed by an allowlist route table.
package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
				// Strip the /api/<svc> prefix from the path, leaving only the downstream path.
				req.Out.URL.Path = strings.TrimPrefix(req.In.URL.Path, "/api/"+svcName)
				if req.Out.URL.Path == "" {
					req.Out.URL.Path = "/"
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

// Forward proxies the request to the named upstream service.
// Returns false and writes a 404 response if the service is not in the allowlist.
func (r *Registry) Forward(c *gin.Context, svc string) {
	rp, ok := r.proxies[svc]
	if !ok {
		httpx.ErrCode(c, http.StatusNotFound, "SERVICE_NOT_FOUND", "service not found in allowlist")

		return
	}

	// Wrap c.Writer in plainResponseWriter to prevent httputil.ReverseProxy from
	// type-asserting to http.CloseNotifier (gin's responseWriter panics when the
	// underlying writer doesn't implement CloseNotify, e.g. httptest.ResponseRecorder).
	rp.ServeHTTP(&plainResponseWriter{ResponseWriter: c.Writer}, c.Request)
}
