// Package config handles environment-first configuration loading for the gateway service.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// minHMACSecretLen is the minimum length (in bytes/chars) required for the
// gateway-origin HMAC secret in non-dev environments (CONVENTIONS §24).
const minHMACSecretLen = 32

// Config holds all configuration for the gateway service.
type Config struct {
	// Server
	Port int    `mapstructure:"port"`
	Env  string `mapstructure:"env"`

	// Logging
	LogLevel string `mapstructure:"log_level"`

	// JWKS / JWT verification
	JWKSUserURL      string `mapstructure:"jwks_user_url"`          // USER_JWKS_URL
	JWKSCacheTTLSec  int    `mapstructure:"jwks_cache_ttl_sec"`     // GATEWAY_JWKS_CACHE_TTL_SEC
	JWKSFetchTimeout int    `mapstructure:"jwks_fetch_timeout_sec"` // GATEWAY_JWKS_FETCH_TIMEOUT_SEC
	JWTIssuer        string `mapstructure:"jwt_issuer"`             // GATEWAY_JWT_ISSUER
	JWTAudience      string `mapstructure:"jwt_audience"`           // GATEWAY_JWT_AUDIENCE
	JWTLeewaySec     int    `mapstructure:"jwt_leeway_sec"`         // GATEWAY_JWT_LEEWAY_SEC

	// Gateway-origin HMAC signing (CONVENTIONS §24).
	// Shared secret used to HMAC-SHA256 sign the injected identity tuple so downstream
	// services can prove the headers originated from the gateway (defense-in-depth,
	// layered on the gateway-sole-JWT-verifier model — NOT a replacement). Each
	// downstream service is configured with the SAME value via <SVC>_GATEWAY_HMAC_SECRET.
	// Production/non-dev: required, MUST be >= minHMACSecretLen chars (fail-fast).
	// Development: empty is allowed and disables signing (parity with empty CORS).
	HMACSecret string `mapstructure:"hmac_secret"` // GATEWAY_HMAC_SECRET

	// Upstream services
	UserUpstreamURL string `mapstructure:"user_upstream_url"` // USER_UPSTREAM_URL
	Upstreams       string `mapstructure:"upstreams"`         // GATEWAY_UPSTREAMS (comma-separated svc=url)

	// CORS — comma-separated allowed origins (e.g. "http://localhost:5500").
	// Empty string disables CORS headers (production: CDN handles it).
	CORSOrigins string `mapstructure:"cors_origins"` // GATEWAY_CORS_ORIGINS

	// Rate limiting
	RateLimitPerMin     int `mapstructure:"rate_limit_per_min"`      // GATEWAY_RATE_LIMIT_PER_MIN
	AuthRateLimitPerMin int `mapstructure:"auth_rate_limit_per_min"` // GATEWAY_AUTH_RATE_LIMIT_PER_MIN
	UserRateLimitPerMin int `mapstructure:"user_rate_limit_per_min"` // GATEWAY_USER_RATE_LIMIT_PER_MIN (default 300)
	UserRateLimitBurst  int `mapstructure:"user_rate_limit_burst"`   // GATEWAY_USER_RATE_LIMIT_BURST (default 30)

	// Proxy
	ProxyTimeoutSec int `mapstructure:"proxy_timeout_sec"` // GATEWAY_PROXY_TIMEOUT_SEC
}

// Load reads configuration from environment variables (prefix GATEWAY_ and USER_).
// Fail-fast at boot: returns an error if any required key is missing or invalid.
func Load() (*Config, error) {
	v := viper.New()

	// ENV-FIRST: set prefix and auto-bind env vars.
	v.SetEnvPrefix("GATEWAY")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Explicit BindEnv for every key to guarantee resolution regardless of prefix.
	// #nosec G101 -- these are config-key→ENV-VAR-NAME mappings, not credential
	// values; "GATEWAY_HMAC_SECRET" is the name of the env var to read, never a secret.
	bindings := map[string]string{
		"port":                    "GATEWAY_PORT",
		"env":                     "GATEWAY_ENV",
		"log_level":               "GATEWAY_LOG_LEVEL",
		"jwks_cache_ttl_sec":      "GATEWAY_JWKS_CACHE_TTL_SEC",
		"jwks_fetch_timeout_sec":  "GATEWAY_JWKS_FETCH_TIMEOUT_SEC",
		"jwt_issuer":              "GATEWAY_JWT_ISSUER",
		"jwt_audience":            "GATEWAY_JWT_AUDIENCE",
		"jwt_leeway_sec":          "GATEWAY_JWT_LEEWAY_SEC",
		"hmac_secret":             "GATEWAY_HMAC_SECRET",
		"upstreams":               "GATEWAY_UPSTREAMS",
		"cors_origins":            "GATEWAY_CORS_ORIGINS",
		"rate_limit_per_min":      "GATEWAY_RATE_LIMIT_PER_MIN",
		"auth_rate_limit_per_min": "GATEWAY_AUTH_RATE_LIMIT_PER_MIN",
		"user_rate_limit_per_min": "GATEWAY_USER_RATE_LIMIT_PER_MIN",
		"user_rate_limit_burst":   "GATEWAY_USER_RATE_LIMIT_BURST",
		"proxy_timeout_sec":       "GATEWAY_PROXY_TIMEOUT_SEC",
		// USER_ prefixed keys (shared with user service).
		"jwks_user_url":     "USER_JWKS_URL",
		"user_upstream_url": "USER_UPSTREAM_URL",
	}

	for key, envKey := range bindings {
		if err := v.BindEnv(key, envKey); err != nil {
			return nil, fmt.Errorf("config bind %q: %w", key, err)
		}
	}

	// Defaults.
	v.SetDefault("port", 8080)
	// NOTE: "env" has NO default. GATEWAY_ENV MUST be set explicitly at boot.
	// An unset GATEWAY_ENV is caught by validate() and causes a fail-fast error —
	// this prevents a production deploy from silently running in dev-mode when the
	// env var is accidentally omitted (fail-closed, not fail-open).
	v.SetDefault("log_level", "INFO")
	v.SetDefault("jwks_cache_ttl_sec", 300)
	v.SetDefault("jwks_fetch_timeout_sec", 5)
	v.SetDefault("jwt_issuer", "coverones-user")
	v.SetDefault("jwt_audience", "coverones")
	v.SetDefault("jwt_leeway_sec", 60)
	v.SetDefault("rate_limit_per_min", 60)
	v.SetDefault("auth_rate_limit_per_min", 20)
	v.SetDefault("user_rate_limit_per_min", 300)
	v.SetDefault("user_rate_limit_burst", 30)
	v.SetDefault("proxy_timeout_sec", 30)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validEnvs is the exhaustive set of allowed GATEWAY_ENV values (case-insensitive).
// GATEWAY_ENV has no default: an unset or unknown value fails fast at boot so that
// production can never silently inherit dev-grade behavior (fail-closed design).
var validEnvs = map[string]bool{
	"development": true,
	"staging":     true,
	"production":  true,
}

func (c *Config) validate() error {
	var errs []string

	if c.Port <= 0 || c.Port > 65535 {
		errs = append(errs, "GATEWAY_PORT must be 1-65535")
	}

	// GATEWAY_ENV must be explicitly set to one of the allowed values.
	// An empty string (env var unset) AND an unknown string (e.g. "prod") are both
	// rejected — "prod" is a common abbreviation that would silently be treated as
	// non-dev (and require HMAC secret) but is still an operator error worth flagging.
	if !validEnvs[strings.ToLower(c.Env)] {
		errs = append(errs, "GATEWAY_ENV must be explicitly set to one of: development, staging, production")
	}

	if c.JWKSUserURL == "" {
		errs = append(errs, "USER_JWKS_URL is required")
	}

	if c.UserUpstreamURL == "" {
		errs = append(errs, "USER_UPSTREAM_URL is required")
	}

	if c.JWKSCacheTTLSec <= 0 {
		errs = append(errs, "GATEWAY_JWKS_CACHE_TTL_SEC must be > 0")
	}

	if c.JWKSFetchTimeout <= 0 {
		errs = append(errs, "GATEWAY_JWKS_FETCH_TIMEOUT_SEC must be > 0")
	}

	if c.RateLimitPerMin <= 0 {
		errs = append(errs, "GATEWAY_RATE_LIMIT_PER_MIN must be > 0")
	}

	if c.AuthRateLimitPerMin <= 0 {
		errs = append(errs, "GATEWAY_AUTH_RATE_LIMIT_PER_MIN must be > 0")
	}

	if c.UserRateLimitPerMin <= 0 {
		errs = append(errs, "GATEWAY_USER_RATE_LIMIT_PER_MIN must be > 0")
	}

	if c.UserRateLimitBurst <= 0 {
		errs = append(errs, "GATEWAY_USER_RATE_LIMIT_BURST must be > 0")
	}

	if c.ProxyTimeoutSec <= 0 {
		errs = append(errs, "GATEWAY_PROXY_TIMEOUT_SEC must be > 0")
	}

	validLogLevels := map[string]bool{"DEBUG": true, "INFO": true, "WARN": true, "ERROR": true}
	if !validLogLevels[strings.ToUpper(c.LogLevel)] {
		errs = append(errs, "GATEWAY_LOG_LEVEL must be DEBUG|INFO|WARN|ERROR")
	}

	errs = append(errs, c.validateHMACSecret()...)

	if len(errs) > 0 {
		return errors.New("config validation failed: " + strings.Join(errs, "; "))
	}

	return nil
}

// validateHMACSecret checks the gateway-origin HMAC secret (CONVENTIONS §24).
// Staging and production MUST set a secret of at least minHMACSecretLen chars so
// downstream can verify header authenticity. Explicitly-set "development" may leave it
// empty (signing disabled — same posture as an empty CORS allowlist). IsDev() is the
// single source of truth; staging is treated identically to production (both are non-dev).
// Extracted from validate() to keep cyclomatic complexity within the gocyclo threshold.
func (c *Config) validateHMACSecret() []string {
	if c.IsDev() {
		return nil
	}

	switch {
	case c.HMACSecret == "":
		return []string{"GATEWAY_HMAC_SECRET is required in non-development environments"}
	case len(c.HMACSecret) < minHMACSecretLen:
		return []string{fmt.Sprintf("GATEWAY_HMAC_SECRET must be at least %d characters", minHMACSecretLen)}
	}

	return nil
}

// IsDev reports whether the service is running in development mode.
func (c *Config) IsDev() bool {
	return strings.EqualFold(c.Env, "development")
}
