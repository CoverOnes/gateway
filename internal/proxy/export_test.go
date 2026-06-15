// Package proxy — test-only exports.
// This file is compiled ONLY when running tests (it lives in package proxy, not proxy_test).
// It exposes internal symbols needed by tests without changing the production API.
package proxy

import "net/http/httputil"

// ProxyForService returns the internal *httputil.ReverseProxy for the named
// service, or (nil, false) if the service is not registered.
// Used by TestProxy_MissingNormalizedPath_DoesNotReachUpstream to drive the
// proxy at the httputil layer (bypassing Forward, which always sets the context
// key).
func (r *Registry) ProxyForService(svc string) (*httputil.ReverseProxy, bool) {
	rp, ok := r.proxies[svc]

	return rp, ok
}
