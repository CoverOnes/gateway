# syntax=docker/dockerfile:1

# ─── Build stage ─────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Cache dependency downloads before copying source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /server ./cmd/server

# ─── Runtime stage ───────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app

# Copy the compiled binary.
COPY --from=builder /server /server

# Run as the built-in nonroot user (uid 65532).
USER nonroot:nonroot

EXPOSE 8080

# Liveness probe — process is serving.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/server", "-healthcheck"] || exit 1

ENTRYPOINT ["/server"]
