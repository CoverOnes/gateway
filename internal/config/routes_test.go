package config_test

import (
	"testing"

	"github.com/CoverOnes/gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func baseConfig() *config.Config {
	return &config.Config{
		Port:                8080,
		Env:                 "development",
		LogLevel:            "INFO",
		JWKSUserURL:         "http://user:8080/jwks",
		JWKSCacheTTLSec:     300,
		JWKSFetchTimeout:    5,
		JWTIssuer:           "coverones-user",
		JWTAudience:         "coverones",
		JWTLeewaySec:        60,
		UserUpstreamURL:     "http://user:8080",
		RateLimitPerMin:     60,
		AuthRateLimitPerMin: 20,
		ProxyTimeoutSec:     30,
	}
}

func TestParseRouteTable_HappyPath(t *testing.T) {
	cfg := baseConfig()

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err)
	require.Contains(t, table, "user")
	assert.Equal(t, "http://user:8080", table["user"].BaseURL)
}

func TestParseRouteTable_WithAdditionalUpstreams(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "project=http://project:8080,contract=http://contract:9000"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err)
	assert.Contains(t, table, "user")
	assert.Contains(t, table, "project")
	assert.Contains(t, table, "contract")
	assert.Equal(t, "http://project:8080", table["project"].BaseURL)
	assert.Equal(t, "http://contract:9000", table["contract"].BaseURL)
}

func TestParseRouteTable_RejectJavascriptScheme(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "evil=javascript://evil.com"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestParseRouteTable_RejectFileScheme(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "evil=file:///etc/passwd"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestParseRouteTable_RejectEmptyHost(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "evil=http://"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host")
}

func TestParseRouteTable_RejectInvalidFormat(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "noequalsign"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "svc=url")
}

func TestParseRouteTable_EmptyUserUpstreamURL(t *testing.T) {
	cfg := baseConfig()
	cfg.UserUpstreamURL = ""

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user upstream")
}

func TestParseRouteTable_TrailingSlashNormalized(t *testing.T) {
	cfg := baseConfig()
	cfg.UserUpstreamURL = "http://user:8080/"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err)
	assert.Equal(t, "http://user:8080", table["user"].BaseURL,
		"trailing slash should be stripped from base URL")
}

func TestParseRouteTable_HttpsSchemeAccepted(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "secure=https://secure-svc:8443"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err)
	assert.Contains(t, table, "secure")
	assert.Equal(t, "https://secure-svc:8443", table["secure"].BaseURL)
}

// ─── SSRF guard tests (G-M4) ─────────────────────────────────────────────────

func TestParseRouteTable_RejectLinkLocalMetadata(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "meta=http://169.254.169.254/latest"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden range", "cloud-metadata IP must be rejected")
}

func TestParseRouteTable_RejectIPv4LinkLocal(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "evil=http://169.254.1.1:80"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden range", "IPv4 link-local must be rejected")
}

func TestParseRouteTable_RejectIPv6LinkLocal(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "evil=http://[fe80::1]:80"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden range", "IPv6 link-local must be rejected")
}

func TestParseRouteTable_RejectIPv4MappedIPv6Metadata(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "meta=http://[::ffff:169.254.169.254]/latest"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden range", "IPv4-mapped IPv6 metadata address must be rejected (NEW-M1 Unmap)")
}

func TestParseRouteTable_AllowPrivateRangeIPv4(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "internal=http://10.0.1.50:8080"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err, "private IPv4 range 10.x must be allowed")
	assert.Contains(t, table, "internal")
}

func TestParseRouteTable_AllowPrivateRangeIPv4_172(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "internal=http://172.16.0.1:9000"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err, "private IPv4 range 172.16/12 must be allowed")
	assert.Contains(t, table, "internal")
}

func TestParseRouteTable_AllowPrivateRangeIPv4_192(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "internal=http://192.168.1.100:8080"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err, "private IPv4 range 192.168/16 must be allowed")
	assert.Contains(t, table, "internal")
}

func TestParseRouteTable_AllowHostname(t *testing.T) {
	cfg := baseConfig()
	cfg.Upstreams = "svc=http://internal-service.default.svc.cluster.local:8080"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err, "internal hostname must always be allowed")
	assert.Contains(t, table, "svc")
}

func TestParseRouteTable_RejectLoopbackInProduction(t *testing.T) {
	cfg := baseConfig()
	cfg.Env = "production"
	cfg.Upstreams = "local=http://127.0.0.1:8080"

	_, err := config.ParseRouteTable(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loopback", "loopback must be rejected in production")
}

func TestParseRouteTable_AllowLoopbackInDevelopment(t *testing.T) {
	cfg := baseConfig()
	cfg.Env = "development"
	cfg.Upstreams = "local=http://127.0.0.1:8080"

	table, err := config.ParseRouteTable(cfg)
	require.NoError(t, err, "loopback must be allowed in development for local integration tests")
	assert.Contains(t, table, "local")
}
