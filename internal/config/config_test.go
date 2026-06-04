package config_test

import (
	"os"
	"testing"

	"github.com/CoverOnes/gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setEnv(t *testing.T, pairs ...string) {
	t.Helper()

	for i := 0; i+1 < len(pairs); i += 2 {
		t.Setenv(pairs[i], pairs[i+1])
	}
}

func minValidEnv(t *testing.T) {
	t.Helper()

	setEnv(
		t,
		"GATEWAY_PORT", "8080",
		"USER_JWKS_URL", "http://user:8080/jwks",
		"USER_UPSTREAM_URL", "http://user:8080",
		"GATEWAY_ENV", "development",
		"GATEWAY_LOG_LEVEL", "INFO",
	)
}

func TestLoad_HappyPath(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_PORT", "9090", "GATEWAY_LOG_LEVEL", "DEBUG")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 9090, cfg.Port)
	assert.Equal(t, "DEBUG", cfg.LogLevel)
	assert.Equal(t, "http://user:8080/jwks", cfg.JWKSUserURL)
	assert.Equal(t, "http://user:8080", cfg.UserUpstreamURL)
}

func TestLoad_MissingUserJwksURL(t *testing.T) {
	minValidEnv(t)
	os.Unsetenv("USER_JWKS_URL") //nolint:errcheck // test cleanup

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_JWKS_URL")
}

func TestLoad_MissingUserUpstreamURL(t *testing.T) {
	minValidEnv(t)
	os.Unsetenv("USER_UPSTREAM_URL") //nolint:errcheck // test cleanup

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_UPSTREAM_URL")
}

func TestLoad_InvalidPort(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_PORT", "99999")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_PORT")
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_LOG_LEVEL", "VERBOSE")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_LOG_LEVEL")
}

func TestLoad_Defaults(t *testing.T) {
	minValidEnv(t)

	os.Unsetenv("GATEWAY_PORT")                    //nolint:errcheck // test cleanup
	os.Unsetenv("GATEWAY_LOG_LEVEL")               //nolint:errcheck // test cleanup
	os.Unsetenv("GATEWAY_JWKS_CACHE_TTL_SEC")      //nolint:errcheck // test cleanup
	os.Unsetenv("GATEWAY_PROXY_TIMEOUT_SEC")       //nolint:errcheck // test cleanup
	os.Unsetenv("GATEWAY_RATE_LIMIT_PER_MIN")      //nolint:errcheck // test cleanup
	os.Unsetenv("GATEWAY_AUTH_RATE_LIMIT_PER_MIN") //nolint:errcheck // test cleanup

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, "INFO", cfg.LogLevel)
	assert.Equal(t, 300, cfg.JWKSCacheTTLSec)
	assert.Equal(t, 30, cfg.ProxyTimeoutSec)
	assert.Equal(t, 60, cfg.RateLimitPerMin)
	assert.Equal(t, 20, cfg.AuthRateLimitPerMin)
}

// TestLoad_RateLimitValuesFlowThroughConfig verifies that GATEWAY_RATE_LIMIT_PER_MIN
// and GATEWAY_AUTH_RATE_LIMIT_PER_MIN are loaded from environment variables and
// reflected in the Config struct (G-M2: config values must not be discarded).
func TestLoad_RateLimitValuesFlowThroughConfig(t *testing.T) {
	minValidEnv(t)
	setEnv(t,
		"GATEWAY_RATE_LIMIT_PER_MIN", "120",
		"GATEWAY_AUTH_RATE_LIMIT_PER_MIN", "40",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 120, cfg.RateLimitPerMin,
		"GATEWAY_RATE_LIMIT_PER_MIN must be loaded from env and not hardcoded")
	assert.Equal(t, 40, cfg.AuthRateLimitPerMin,
		"GATEWAY_AUTH_RATE_LIMIT_PER_MIN must be loaded from env and not hardcoded")
}

// TestLoad_InvalidRateLimitRejected ensures the validator catches bad rate-limit values.
func TestLoad_InvalidRateLimitRejected(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_RATE_LIMIT_PER_MIN", "0")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_RATE_LIMIT_PER_MIN")
}

// validProdSecret is a 32+ char value used to exercise the non-dev HMAC fail-fast.
const validProdSecret = "prod-gateway-hmac-secret-0123456789ABCDEF"

// TestLoad_DevAllowsEmptyHMACSecret asserts development mode does NOT require the
// gateway-origin HMAC secret (signing is disabled in dev — parity with empty CORS).
func TestLoad_DevAllowsEmptyHMACSecret(t *testing.T) {
	minValidEnv(t) // GATEWAY_ENV=development, no GATEWAY_HMAC_SECRET

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.HMACSecret, "dev mode leaves the HMAC secret unset → signing disabled")
}

// TestLoad_NonDevRequiresHMACSecret asserts production/non-dev fails fast when the
// gateway-origin HMAC secret is missing (CONVENTIONS §24).
func TestLoad_NonDevRequiresHMACSecret(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_ENV", "production") // no GATEWAY_HMAC_SECRET set

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_HMAC_SECRET")
}

// TestLoad_NonDevRejectsShortHMACSecret asserts a too-short secret is rejected in
// non-dev: the minimum length bounds brute-force feasibility of the shared key.
func TestLoad_NonDevRejectsShortHMACSecret(t *testing.T) {
	minValidEnv(t)
	setEnv(t,
		"GATEWAY_ENV", "production",
		"GATEWAY_HMAC_SECRET", "too-short", // < 32 chars
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 characters")
}

// TestLoad_NonDevWithValidHMACSecretPasses asserts a valid non-dev config loads and
// the secret flows through to the Config struct unchanged.
func TestLoad_NonDevWithValidHMACSecretPasses(t *testing.T) {
	minValidEnv(t)
	setEnv(t,
		"GATEWAY_ENV", "production",
		"GATEWAY_HMAC_SECRET", validProdSecret,
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, validProdSecret, cfg.HMACSecret,
		"GATEWAY_HMAC_SECRET must flow through to config unchanged")
}
