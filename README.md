# CoverOnes Gateway

Stateless API gateway — the single public entry point for all CoverOnes platform traffic.

## What it does

- Validates the caller's access token and rejects unauthenticated requests before they reach any backend service
- Injects trusted identity headers so downstream services receive a verified caller context
- Applies per-IP rate limiting (global + tighter limit on auth routes) and CORS enforcement
- Strips any client-supplied identity headers to prevent spoofing
- Routes authenticated requests to the correct backend service via a configurable route table
- Maintains a refreshed JWKS cache to verify tokens without round-tripping the user service on every request

## Where it sits

The gateway is the only service exposed to the internet. All other services (user, kyc, etc.) run on the internal network and trust the identity context the gateway injects. Public auth routes (`/v1/auth/*`) are forwarded without a token; all other API routes require a valid access token and are proxied under `/api/:svc/*`.

## API (high level)

| Group | Endpoints | Notes |
|-------|-----------|-------|
| `GET /healthz`, `GET /readyz` | Liveness / readiness probes | Not rate-limited |
| `GET /jwks` | Forward public key set from user service | Public, cache-friendly |
| `POST /v1/auth/*` | register / login / refresh / verify-email / resend-verification / logout | Public (except logout); tighter rate limit |
| `ANY /api/:svc/*` | Proxy to named backend service | Requires valid access token |

Request/response shapes follow the platform envelope; see `../conventions/http-api.md`.

## Tech

| Item | Choice |
|------|--------|
| Language | Go 1.25 |
| HTTP framework | Gin v1.12 |
| Token verification | golang-jwt/jwt v5 |
| Logging | slog JSON to stdout |

## Run locally

This service is part of the shared dev stack — see `../dev-stack/README.md`.
