# CoverOnes Platform Conventions

Cross-service conventions all CoverOnes microservices MUST follow. This document is the source of truth; each service copies this file at bootstrap and verifies compliance before PR merge.

---

## 1. Response Envelope

All JSON endpoints use a consistent envelope shape.

**Success:**
```json
{ "data": <payload> }
```

**Error:**
```json
{
  "error": {
    "code": "UPPER_SNAKE",
    "message": "human readable description",
    "details": { "...optional structured data..." }
  }
}
```

- 204 No Content: logout and other destructive acks (no body).
- Lives in `internal/platform/httpx/envelope.go` — copy this exactly across services.
- Machine codes are stable UPPER_SNAKE: `VALIDATION_ERROR`, `UNAUTHORIZED`, `KYC_TIER_REQUIRED`, `RATE_LIMITED`, `EMAIL_TAKEN`, `INVALID_CREDENTIALS`, `ACCOUNT_SUSPENDED`, `INTERNAL_ERROR`, etc.
- NEVER leak internal driver errors, SQL error messages, or stack traces to clients.

---

## 2. Error Codes (Central Table)

| Code | HTTP Status | Trigger |
|------|-------------|---------|
| `VALIDATION_ERROR` | 400 | Request body / param validation failure |
| `UNAUTHORIZED` | 401 | Missing or invalid Bearer token |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password (generic — no user enumeration) |
| `INVALID_REFRESH_TOKEN` | 401 | Refresh token not found / hash mismatch |
| `REFRESH_EXPIRED` | 401 | Token past expires_at |
| `REFRESH_REUSE_DETECTED` | 401 | Token already consumed (family revoked) |
| `ACCOUNT_SUSPENDED` | 403 | User.status = SUSPENDED |
| `KYC_TIER_REQUIRED` | 403 | kycTier in token < required tier |
| `EMAIL_TAKEN` | 409 | Registration with already-registered email |
| `WEAK_PASSWORD` | 422 | Password fails complexity check |
| `RATE_LIMITED` | 429 | IP or account rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Unhandled server error |

---

## 3. Config Pattern (ENV-FIRST)

Every service uses Viper with:
```go
v.SetEnvPrefix("<SVC>")   // e.g. "USER"
v.AutomaticEnv()
v.BindEnv(key, "SVC_KEY") // explicit BindEnv for every key
```

- Struct-based `Config` with `validate()` at boot — fail fast on missing secrets.
- `.env` file only for local dev via godotenv, never committed.
- `.env.example` documents every key with `REPLACE_ME` placeholders.
- Env vars are the ONLY production path; file is a local convenience.

---

## 4. Secrets Policy

- ALL secrets (DB DSN, JWT private key, Redis URL, API keys) from env or Secrets Manager ONLY.
- NEVER in git, NEVER in DB, NEVER logged.
- `block-sensitive-add.sh` git hook + CI secret scan enforces this.
- Credential-bearing files at runtime: `os.Stat` to verify `Mode().Perm() & 0o077 == 0`; emit `slog.Warn` if permissive.

---

## 5. Logging (slog)

- `slog.New(slog.NewJSONHandler(os.Stdout, ...))` as the default logger.
- Level from env (default INFO).
- Attach `request_id` and (when authenticated) `user_id` from context to every log line.
- One logger constructor in `internal/platform/logger/slog.go`.
- **No PII in logs**: email, password, tokens MUST be redacted (`[REDACTED]`).
- Hook binaries (PreToolUse / PostToolUse): slog must write to file, NOT stderr (stderr surfaces to terminal).

---

## 6. Health Contract

| Endpoint | Auth | Semantic |
|----------|------|---------|
| `GET /healthz` | public | Liveness — always 200 if process serves; zero dependency checks |
| `GET /readyz` | public | Readiness — pings all critical deps; 200 `{status:ready,checks:{...}}` or 503 `NOT_READY` |

k8s/Railway probes wire to these endpoints. NEVER add auth to health endpoints.

---

## 7. Request-ID Middleware

- Read `X-Request-ID` inbound or generate `uuid.New().String()`.
- Echo in response header `X-Request-ID`.
- Inject into request context and every log line via `logger.WithRequestID(ctx, rid)`.
- Propagate downstream on service-to-service calls via `X-Request-ID` header.

---

## 8. Security Headers Middleware

Apply to every response:

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Content-Security-Policy` | `default-src 'none'` (API services) |

Auth endpoints additionally: `Cache-Control: no-store`.

TLS 1.3 terminated at edge (Railway / ingress) — services themselves listen plain HTTP internally.

---

## 9. Middleware Chain Order

```
recover -> request-id -> security-headers -> slog access-log -> CORS -> rate-limit -> auth (per-route)
```

- Deny-by-default: routes without explicit auth + min-tier declaration are NOT registered.
- Rate limiting via Redis; nil Redis = pass-through in dev.

---

## 10. Auth Middleware & KYC Tier Gate

- Bearer JWT verified offline using local JWKS cache (from user service `/jwks`, `max-age=300s`).
- `RequireTier(n)` middleware returns `403 KYC_TIER_REQUIRED {requiredTier, currentTier}` when `token.kycTier < n`.
- Each protected route declares `min_tier` explicitly in the router (deny-by-default per spec §7.3).
- `WithValidMethods(["EdDSA"])` — reject `alg=none` and any HS*/RS* algorithms.

---

## 11. Migration Convention

- Tool: `golang-migrate`, files `migrations/{NNNNNN}_{snake_desc}.{up,down}.sql`.
- Monotonic 6-digit prefix.
- **Plain SQL only** in `.down.sql` — NO psql metacommands (`\set`, `:variable`, `\copy`).
- Migrations are **immutable once merged to master** — corrections via new numbered migration.
- Embedded via `//go:embed migrations/*.sql` for single-binary deploy.
- **ZERO foreign keys** platform-wide — indexes encouraged.
- Platform: `timestamptz` stored UTC; all PKs `uuid`.

---

## 12. pgxpool Configuration (Postgres)

```go
cfg.MaxConns = 10
cfg.MinConns = 2
cfg.MaxConnLifetime = 30 * time.Minute
cfg.MaxConnIdleTime = 5 * time.Minute
cfg.HealthCheckPeriod = 1 * time.Minute
```

Pool created once at boot, injected via DI, pinged in `/readyz`.
`(service replicas × MaxConns) < Postgres max_connections`.

---

## 13. ID & Time Types

- All PKs: `uuid` (Postgres `gen_random_uuid()`; app also generates via `github.com/google/uuid`).
- All timestamps: `timestamptz` stored UTC; JSON serialises RFC3339.
- Money/decimals: never `float` (future services use `numeric`/`decimal`).

---

## 14. Redis Event Naming (pub/sub)

- Channel pattern: dotted lowercase `<domain>.<event>`.
  - e.g. `kyc.tier_changed`, `user.suspended`, `user.erased`
- Payload envelope:
  ```json
  { "eventId": "<uuid>", "occurredAt": "<rfc3339>", "version": 1, "data": { "..." } }
  ```
- User service:
  - **Subscribes**: `kyc.tier_changed` → update `users.kyc_tier`
  - **Publishes**: `user.*` lifecycle events (suspended, erased, registered)

---

## 15. GDPR / PII Policy

| Column type | Treatment |
|-------------|-----------|
| Email | Low-sensitivity PII — plaintext (citext), partial-unique-index, GDPR-erasable |
| Password hash | Never returned in API, never logged |
| High-sensitivity PII (KYC docs, national ID) | AES-256-GCM field encryption — deferred to KYC service |

- Right-to-erasure: `deleted_at` soft-delete + scrub identifying columns; hard-purge job after 30 days.
- Observability tables (refresh_tokens, audit) **MUST** have TTL/retention implemented in the same PR that adds the table.
- Data minimisation: only store what the service actually needs.

---

## 16. Testing Standards

- **testcontainers** Postgres for every store integration test (no mocks, no shared dev DB).
- Table-driven unit tests; `testing.Short()` guard on integration tests.
- `task check` (`golangci-lint v2 + go vet + go test`) green before any PR.
- `gosec` G101/G107 NEVER excluded.

---

## 17. Docker Standards

- Multi-stage: `golang:1.25-alpine` builder → `distroless/static-debian12:nonroot` runtime.
- Non-root: `USER nonroot:nonroot` (uid 65532).
- `HEALTHCHECK` pointing to `/healthz`.
- `.dockerignore` excludes `.env`, `.git`, test files.
- Binary built with `-trimpath -ldflags="-s -w"` for minimal size.

---

## 18. Shared Code Policy

Do NOT create a `github.com/CoverOnes/common` Go module yet (first 1-2 services).
Copy the small platform layer (`httpx`, `logger`, `middleware`, `health`) into each repo.

**Rationale**: a shared module introduces cross-repo version coupling before conventions stabilise. Re-evaluate extracting `common` once 3 services exist and duplicated code has provably converged. The JWKS verify helper is the strongest future extraction candidate.

---

## 19. JWT Design (EdDSA / Ed25519)

- Algorithm: `EdDSA` (Ed25519) ONLY. Verifiers MUST call `WithValidMethods(["EdDSA"])`.
- Key storage: 32-byte seed in `USER_JWT_ED25519_PRIVATE_KEY` (base64) or PEM via `USER_JWT_ED25519_PRIVATE_KEY_PEM`. NEVER in DB or git.
- KID: `base64url(SHA-256(publicKey))[:16]` — deterministic from public key.
- Access token claims: `iss`, `sub`, `aud`, `kycTier`, `accountType`, `tokenVersion`, `iat`, `exp`, `jti`.
- Expiry: `exp <= iat + 600s` (10 minutes).
- Downstream services verify OFFLINE using `/jwks` (cached, `max-age=300`).
- Clock skew tolerance: 60s leeway.

---

## 20. Refresh Token Design

- Format: opaque `<id>.<secret>` where id is the row UUID and secret is `base64url(32 random bytes)`.
- DB stores only `SHA-256(secret)` in `token_hash` (bytea). Raw token NEVER stored.
- Rotation: each `/refresh` creates new row (same `family_id`, `prev_id` = old id), marks old as used.
- Reuse detection: `used_at IS NOT NULL` on presented token → revoke whole family → 401.
- Expiry: `expires_at = issued + 24h`.
- Retention: scheduled `DELETE WHERE expires_at < now() - interval '7 days'` (forensic grace window).
