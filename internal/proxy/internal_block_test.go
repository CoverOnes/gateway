package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUpstreamPath verifies that the path normalisation (prefix stripping,
// percent-decode, path.Clean) produces the correct upstream path for a variety
// of input shapes.
func TestUpstreamPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		requestPath string
		svc         string
		want        string
		wantValid   bool
	}{
		{
			name:        "simple public path",
			requestPath: "/api/kyc/v1/kyc/me",
			svc:         "kyc",
			want:        "/v1/kyc/me",
			wantValid:   true,
		},
		{
			name:        "direct internal prefix",
			requestPath: "/api/kyc/internal/v1/kyc/abc/status",
			svc:         "kyc",
			want:        "/internal/v1/kyc/abc/status",
			wantValid:   true,
		},
		{
			name:        "mid-path internal segment",
			requestPath: "/api/kyc/v1/foo/internal/bar",
			svc:         "kyc",
			want:        "/v1/foo/internal/bar",
			wantValid:   true,
		},
		{
			name:        "dot-dot traversal into internal",
			requestPath: "/api/kyc/foo/../internal/status",
			svc:         "kyc",
			want:        "/internal/status",
			wantValid:   true,
		},
		{
			name:        "double-slash collapsed",
			requestPath: "/api/kyc//internal/v1",
			svc:         "kyc",
			want:        "/internal/v1",
			wantValid:   true,
		},
		{
			name:        "percent-encoded slash before internal",
			requestPath: "/api/kyc/%2finternal/v1",
			svc:         "kyc",
			want:        "/internal/v1",
			wantValid:   true,
		},
		{
			name:        "percent-encoded dot-dot traversal",
			requestPath: "/api/kyc/foo/%2e%2e/internal/v1",
			svc:         "kyc",
			want:        "/internal/v1",
			wantValid:   true,
		},
		{
			name:        "no svc prefix match — unchanged",
			requestPath: "/api/user/v1/me",
			svc:         "user",
			want:        "/v1/me",
			wantValid:   true,
		},
		{
			name:        "empty after prefix strip → root",
			requestPath: "/api/kyc",
			svc:         "kyc",
			want:        "/",
			wantValid:   true,
		},
		// M1 — null-byte bypass: %00 decodes to \x00; path is invalid.
		{
			name:        "null byte via %00 is invalid",
			requestPath: "/api/kyc/%00internal/v1",
			svc:         "kyc",
			want:        "",
			wantValid:   false,
		},
		{
			name:        "null byte after internal segment is invalid",
			requestPath: "/api/kyc/internal%00/v1",
			svc:         "kyc",
			want:        "",
			wantValid:   false,
		},
		// M1 — CRLF injection.
		{
			name:        "carriage-return in path is invalid",
			requestPath: "/api/kyc/v1%0d/me",
			svc:         "kyc",
			want:        "",
			wantValid:   false,
		},
		{
			name:        "newline in path is invalid",
			requestPath: "/api/kyc/v1%0a/me",
			svc:         "kyc",
			want:        "",
			wantValid:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, valid := upstreamPath(tc.requestPath, tc.svc)
			assert.Equal(t, tc.wantValid, valid, "valid flag mismatch for requestPath=%q", tc.requestPath)
			if tc.wantValid {
				assert.Equal(t, tc.want, got, "path mismatch for requestPath=%q", tc.requestPath)
			}
		})
	}
}

// TestContainsInternalSegment verifies that the segment-level check correctly
// identifies cleaned paths that contain an "internal" segment.
func TestContainsInternalSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cleanedPath string
		want        bool
	}{
		// Paths that MUST be blocked
		{
			name:        "direct internal prefix",
			cleanedPath: "/internal/v1/kyc/abc/status",
			want:        true,
		},
		{
			name:        "internal mid-path",
			cleanedPath: "/v1/foo/internal/bar",
			want:        true,
		},
		{
			name:        "internal at end",
			cleanedPath: "/v1/foo/internal",
			want:        true,
		},
		{
			name:        "capital-I Internal is blocked (case-insensitive)",
			cleanedPath: "/Internal/v1/kyc/abc/status",
			want:        true,
		},
		{
			name:        "all-caps INTERNAL is blocked (case-insensitive)",
			cleanedPath: "/INTERNAL/v1/status",
			want:        true,
		},
		{
			name:        "mixed-case iNtErNaL is blocked (case-insensitive)",
			cleanedPath: "/v1/iNtErNaL/bar",
			want:        true,
		},
		// M2 — Trailing-dot bypass: path.Clean preserves "internal." but some
		// upstreams strip trailing dots and route to /internal/*.
		{
			name:        "trailing-dot segment internal. is blocked",
			cleanedPath: "/internal./v1",
			want:        true,
		},
		{
			name:        "double trailing-dot segment internal.. is blocked",
			cleanedPath: "/v1/internal../resource",
			want:        true,
		},
		{
			name:        "mixed-case with trailing dot Internal. is blocked",
			cleanedPath: "/Internal./v1",
			want:        true,
		},
		// Paths that MUST NOT be blocked — "internal" is a substring but not a segment
		{
			name:        "internalize is not internal",
			cleanedPath: "/v1/internalize/resource",
			want:        false,
		},
		{
			name:        "internal-dashboard is not internal",
			cleanedPath: "/v1/internal-dashboard/status",
			want:        false,
		},
		// Normal public paths
		{
			name:        "simple public path",
			cleanedPath: "/v1/kyc/me",
			want:        false,
		},
		{
			name:        "root path",
			cleanedPath: "/",
			want:        false,
		},
		{
			name:        "multi-segment public path",
			cleanedPath: "/v1/contracts/abc123/parties",
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := containsInternalSegment(tc.cleanedPath)
			assert.Equal(t, tc.want, got, "cleanedPath=%q", tc.cleanedPath)
		})
	}
}
