// Package config handles environment-first configuration loading for the gateway service.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

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

	// Upstream services
	UserUpstreamURL string `mapstructure:"user_upstream_url"` // USER_UPSTREAM_URL
	Upstreams       string `mapstructure:"upstreams"`         // GATEWAY_UPSTREAMS (comma-separated svc=url)

	// Rate limiting
	RateLimitPerMin     int `mapstructure:"rate_limit_per_min"`      // GATEWAY_RATE_LIMIT_PER_MIN
	AuthRateLimitPerMin int `mapstructure:"auth_rate_limit_per_min"` // GATEWAY_AUTH_RATE_LIMIT_PER_MIN

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
	bindings := map[string]string{
		"port":                    "GATEWAY_PORT",
		"env":                     "GATEWAY_ENV",
		"log_level":               "GATEWAY_LOG_LEVEL",
		"jwks_cache_ttl_sec":      "GATEWAY_JWKS_CACHE_TTL_SEC",
		"jwks_fetch_timeout_sec":  "GATEWAY_JWKS_FETCH_TIMEOUT_SEC",
		"jwt_issuer":              "GATEWAY_JWT_ISSUER",
		"jwt_audience":            "GATEWAY_JWT_AUDIENCE",
		"jwt_leeway_sec":          "GATEWAY_JWT_LEEWAY_SEC",
		"upstreams":               "GATEWAY_UPSTREAMS",
		"rate_limit_per_min":      "GATEWAY_RATE_LIMIT_PER_MIN",
		"auth_rate_limit_per_min": "GATEWAY_AUTH_RATE_LIMIT_PER_MIN",
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
	v.SetDefault("env", "development")
	v.SetDefault("log_level", "INFO")
	v.SetDefault("jwks_cache_ttl_sec", 300)
	v.SetDefault("jwks_fetch_timeout_sec", 5)
	v.SetDefault("jwt_issuer", "coverones-user")
	v.SetDefault("jwt_audience", "coverones")
	v.SetDefault("jwt_leeway_sec", 60)
	v.SetDefault("rate_limit_per_min", 60)
	v.SetDefault("auth_rate_limit_per_min", 20)
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

func (c *Config) validate() error {
	var errs []string

	if c.Port <= 0 || c.Port > 65535 {
		errs = append(errs, "GATEWAY_PORT must be 1-65535")
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

	if c.ProxyTimeoutSec <= 0 {
		errs = append(errs, "GATEWAY_PROXY_TIMEOUT_SEC must be > 0")
	}

	validLogLevels := map[string]bool{"DEBUG": true, "INFO": true, "WARN": true, "ERROR": true}
	if !validLogLevels[strings.ToUpper(c.LogLevel)] {
		errs = append(errs, "GATEWAY_LOG_LEVEL must be DEBUG|INFO|WARN|ERROR")
	}

	if len(errs) > 0 {
		return errors.New("config validation failed: " + strings.Join(errs, "; "))
	}

	return nil
}

// IsDev reports whether the service is running in development mode.
func (c *Config) IsDev() bool {
	return strings.EqualFold(c.Env, "development")
}
