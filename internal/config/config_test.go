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
	setEnv(
		t,
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

// TestLoad_UserRateLimitBurstFlowsThrough verifies GATEWAY_USER_RATE_LIMIT_BURST is
// loaded from env and reflected in the Config struct.
func TestLoad_UserRateLimitBurstFlowsThrough(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_USER_RATE_LIMIT_BURST", "50")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 50, cfg.UserRateLimitBurst,
		"GATEWAY_USER_RATE_LIMIT_BURST must be loaded from env and reflected in Config")
}

// TestLoad_UserRateLimitBurstDefaultIs30 verifies the default burst is 30.
func TestLoad_UserRateLimitBurstDefaultIs30(t *testing.T) {
	minValidEnv(t)
	os.Unsetenv("GATEWAY_USER_RATE_LIMIT_BURST") //nolint:errcheck // test cleanup

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 30, cfg.UserRateLimitBurst,
		"GATEWAY_USER_RATE_LIMIT_BURST must default to 30")
}

// TestLoad_UserRateLimitBurstZeroRejected ensures burst=0 is rejected at boot.
func TestLoad_UserRateLimitBurstZeroRejected(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_USER_RATE_LIMIT_BURST", "0")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_USER_RATE_LIMIT_BURST")
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
	setEnv(
		t,
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
	setEnv(
		t,
		"GATEWAY_ENV", "production",
		"GATEWAY_HMAC_SECRET", validProdSecret,
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, validProdSecret, cfg.HMACSecret,
		"GATEWAY_HMAC_SECRET must flow through to config unchanged")
}

// TestLoad_EnvMustBeExplicitlySet asserts that omitting GATEWAY_ENV entirely causes a
// boot-time validation error. Without this, an unset env var would have previously
// defaulted to "development" (via viper.SetDefault), silently disabling HMAC signing
// in production. The env variable must now be explicitly set (fail-closed).
func TestLoad_EnvMustBeExplicitlySet(t *testing.T) {
	minValidEnv(t)
	os.Unsetenv("GATEWAY_ENV") //nolint:errcheck // test cleanup; t.Setenv restores on test end

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_ENV")
}

// TestLoad_UnknownEnvValueIsRejected asserts that an unrecognized GATEWAY_ENV value
// (e.g. "prod" — a common abbreviation that is NOT an allowed token) causes a
// validation error. This prevents a misconfigured deploy from running in an ambiguous
// state where the gateway behavior is undefined.
func TestLoad_UnknownEnvValueIsRejected(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_ENV", "prod") // common abbreviation, NOT an allowed value

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_ENV")
}

// TestLoad_StagingEnvWithHMACSecretPasses asserts that "staging" is a valid GATEWAY_ENV
// and — because staging is non-dev — also requires GATEWAY_HMAC_SECRET. This exercises
// the !IsDev() gate and verifies staging is treated identically to production for the
// HMAC requirement.
func TestLoad_StagingEnvWithHMACSecretPasses(t *testing.T) {
	minValidEnv(t)
	setEnv(
		t,
		"GATEWAY_ENV", "staging",
		"GATEWAY_HMAC_SECRET", validProdSecret,
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.False(t, cfg.IsDev(), "staging must not be treated as development")
	assert.Equal(t, validProdSecret, cfg.HMACSecret)
}

// TestLoad_StagingWithoutHMACSecretFails asserts staging requires the HMAC secret:
// the HMAC fail-fast must fire on staging just as it does on production.
func TestLoad_StagingWithoutHMACSecretFails(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "GATEWAY_ENV", "staging") // no GATEWAY_HMAC_SECRET

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GATEWAY_HMAC_SECRET")
}

// ─── JWKS URL SSRF validation tests (Major finding 5) ─────────────────────────

// TestLoad_JWKSURLLinkLocalRejected asserts that a link-local / cloud-metadata IP
// in USER_JWKS_URL is rejected at boot to prevent SSRF via the JWKS fetcher.
func TestLoad_JWKSURLLinkLocalRejected(t *testing.T) {
	minValidEnv(t)
	// 169.254.169.254 is the AWS/GCP metadata endpoint — always forbidden.
	setEnv(t, "USER_JWKS_URL", "http://169.254.169.254/jwks")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_JWKS_URL")
}

// TestLoad_JWKSURLLoopbackRejectedInProd asserts that a loopback address in
// USER_JWKS_URL is rejected in production (allowed in development).
func TestLoad_JWKSURLLoopbackRejectedInProd(t *testing.T) {
	minValidEnv(t)
	setEnv(
		t,
		"GATEWAY_ENV", "production",
		"GATEWAY_HMAC_SECRET", validProdSecret,
		"USER_JWKS_URL", "http://127.0.0.1:8080/jwks",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_JWKS_URL")
}

// TestLoad_JWKSURLLoopbackAllowedInDev asserts that loopback is allowed in
// development (so local integration tests can run without modifying /etc/hosts).
func TestLoad_JWKSURLLoopbackAllowedInDev(t *testing.T) {
	minValidEnv(t)
	// GATEWAY_ENV=development already set by minValidEnv.
	setEnv(t, "USER_JWKS_URL", "http://127.0.0.1:8080/jwks")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/jwks", cfg.JWKSUserURL)
}

// TestLoad_JWKSURLUnsupportedSchemeRejected asserts that non-http/https schemes
// in USER_JWKS_URL are rejected (e.g. file:// or ftp://).
func TestLoad_JWKSURLUnsupportedSchemeRejected(t *testing.T) {
	minValidEnv(t)
	setEnv(t, "USER_JWKS_URL", "file:///etc/passwd")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_JWKS_URL")
}
