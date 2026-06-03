package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name      string
		origins   []string
		reqOrigin string
		method    string
		wantACAO  string // expected Access-Control-Allow-Origin
		wantCode  int
	}{
		{"allowed origin GET", []string{"http://a.com"}, "http://a.com", http.MethodGet, "http://a.com", http.StatusOK},
		{"disallowed origin gets no CORS headers", []string{"http://a.com"}, "http://b.com", http.MethodGet, "", http.StatusOK},
		{"no Origin header is passthrough", []string{"http://a.com"}, "", http.MethodGet, "", http.StatusOK},
		{"preflight OPTIONS short-circuits 204", []string{"http://a.com"}, "http://a.com", http.MethodOptions, "http://a.com", http.StatusNoContent},
		{"empty allowlist is no-op", []string{}, "http://a.com", http.MethodGet, "", http.StatusOK},
		{"wildcard entry is never honored", []string{"*"}, "*", http.MethodGet, "", http.StatusOK},
		{"null entry is never honored", []string{"null"}, "null", http.MethodGet, "", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(CORS(tc.origins))
			r.Any("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

			req := httptest.NewRequestWithContext(context.Background(), tc.method, "/x", http.NoBody)
			if tc.reqOrigin != "" {
				req.Header.Set("Origin", tc.reqOrigin)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if got := w.Header().Get("Access-Control-Allow-Origin"); got != tc.wantACAO {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tc.wantACAO)
			}
			if w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantCode)
			}
			// Credentials must never combine with a wildcard origin (CWE-942).
			if w.Header().Get("Access-Control-Allow-Origin") == "*" {
				t.Error("Access-Control-Allow-Origin must never be * (credentials are allowed)")
			}
		})
	}
}
