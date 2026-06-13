package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CoverOnes/gateway/internal/proxy"
	"github.com/gin-gonic/gin"
)

// Gateway-origin signature headers (CONVENTIONS §24). The gateway HMAC-signs the
// injected identity tuple so downstream services can prove the identity headers
// came from the gateway, not from anything that can reach the service port on the
// internal network. Defense-in-depth layered on the gateway-sole-JWT-verifier
// model — NOT a replacement.
const (
	headerGatewayTs        = "X-Gateway-Ts"
	headerGatewaySignature = "X-Gateway-Signature"
)

// uploadRoutes is the allowlist of (method, path-prefix) pairs for which the
// gateway signer skips reading/buffering the body and instead uses
// bodyHashHex = hex(sha256("")) in the canonical string.
//
// Rationale: these are large-body multipart routes. Buffering the body here
// would (a) truncate uploads >1 MB and (b) require re-streaming gigabytes for
// every upload. The body-hash is replaced by the empty-body sentinel on BOTH the
// gateway signer and the matching downstream verifier so both sides produce an
// identical canonical string. Method + path binding still prevents cross-endpoint
// replay regardless of body size; the 30 s skew window remains the primary replay
// bound.
//
// LOCKSTEP CONTRACT: for every entry (method, pathPrefix) here, the downstream
// service's verifier MUST list the same matching rule using the same empty-body
// sentinel. Currently:
//
//	POST  /api/file/v1/files  ↔  file service verifier: POST /v1/files
//
// When new large-body upload endpoints are added, BOTH this allowlist and the
// corresponding verifier allowlist must be updated in the same PR.
var uploadRoutes = []uploadRoute{
	{method: "POST", pathPrefix: "/api/file/v1/files"},
}

type uploadRoute struct {
	method     string
	pathPrefix string
}

// isUploadRoute reports whether the given method + path matches an entry in the
// upload allowlist. The path match is exact OR prefix-followed-by-'/' so that
// future sub-routes (e.g. /api/file/v1/files/batch) can be added by extending
// uploadRoutes without changing this function.
//
// The guard REQUIRES a '/' separator after the prefix to prevent false-matches
// on sibling paths such as /api/file/v1/files-batch or /api/file/v1/filesx:
// those share the "/api/file/v1/files" prefix but are NOT upload routes and must
// not use the empty-body sentinel.
func isUploadRoute(method, path string) bool {
	for _, r := range uploadRoutes {
		if method != r.method {
			continue
		}

		if path == r.pathPrefix {
			return true
		}

		// Allow sub-paths (e.g. /api/file/v1/files/123) but require '/' separator
		// so /api/file/v1/files-batch and /api/file/v1/filesx do not match.
		if len(path) > len(r.pathPrefix) && path[len(r.pathPrefix)] == '/' &&
			path[:len(r.pathPrefix)] == r.pathPrefix {
			return true
		}
	}

	return false
}

// identityHeaders lists all client-supplied identity headers that MUST be stripped
// before forwarding to upstream services to prevent spoofing attacks.
//
// Implicit contract — strip-list vs inject-list are deliberately asymmetric:
//   - ALL headers below are STRIPPED on every request (StripIdentityHeaders +
//     InjectIdentity Step 1), so a client can never spoof any of them.
//   - Only X-User-Id, X-Kyc-Tier, X-Account-Type, and X-Email-Verified are
//     RE-INJECTED from the verified JWT claims (InjectIdentity Step 2). Upstreams
//     may trust these.
//   - X-User-Email and X-User-Role are intentionally NOT injected: the gateway
//     does not vouch for them. They appear here only to be stripped — upstreams
//     must NEVER treat an inbound X-User-Email / X-User-Role as authoritative,
//     because the gateway guarantees only their absence, not their value.
//
// If a future claim (e.g. email/role) becomes gateway-vouched, it MUST be added
// to InjectIdentity Step 2 below as well — adding it here alone only strips it.
//
// The two gateway-origin signature headers (X-Gateway-Ts, X-Gateway-Signature)
// are ALSO stripped on every request: a client must never be able to pre-seed
// them. Only InjectIdentity (Step 3) re-sets them, computed over the gateway's
// own injected values. A request that reaches an upstream with these headers set
// therefore proves they were produced by the gateway.
var identityHeaders = []string{
	"X-User-Id",
	"X-Kyc-Tier",
	"X-Account-Type",
	"X-Email-Verified",
	"X-User-Email",
	"X-User-Role",
	headerGatewayTs,
	headerGatewaySignature,
}

// StripIdentityHeaders removes all identity headers from the inbound request.
// It performs ONLY deletion — no values are set — making it safe to register
// globally on every route (including public ones).
//
// This provides defense-in-depth: even if a client sends X-User-Id on a public
// route (/v1/auth/login, /jwks, etc.), the upstream will never see it.
// Protected routes additionally run InjectIdentity (Del + Set from verified JWT claims).
func StripIdentityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, h := range identityHeaders {
			c.Request.Header.Del(h)
		}

		c.Next()
	}
}

// InjectIdentity strips any client-supplied identity headers and replaces them with
// values derived from the verified JWT claims. This is the anti-spoofing boundary.
//
// When hmacSecret is non-empty it ALSO sets the gateway-origin signature headers
// (X-Gateway-Ts, X-Gateway-Signature) so downstream services can verify the
// identity headers actually came from the gateway (CONVENTIONS §24). An empty
// secret disables signing — used in development only; non-dev config fails fast
// if the secret is unset (see config.validate).
//
// MUST run AFTER the Auth middleware — it reads claims from context.
// Routes without Auth do NOT get InjectIdentity (they forward no identity headers).
func InjectIdentity(hmacSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Step 1: STRIP all inbound identity headers (prevent client spoofing).
		for _, h := range identityHeaders {
			c.Request.Header.Del(h)
		}

		// Step 2: SET headers from verified JWT claims only.
		claims, ok := ClaimsFromCtx(c)
		if !ok {
			// Auth middleware should have rejected unauthenticated requests before
			// InjectIdentity runs. This is a belt-and-suspenders guard.
			c.Next()

			return
		}

		c.Request.Header.Set("X-User-Id", claims.Subject)
		c.Request.Header.Set("X-Kyc-Tier", strconv.Itoa(int(claims.KYCTier)))
		c.Request.Header.Set("X-Account-Type", claims.AccountType)
		// Fail-safe: an older token without the email_verified claim leaves
		// claims.EmailVerified at its zero value (false), so this injects
		// "false" — never an empty or "true" header for an unverified user.
		//
		// Cross-service string contract (TIGHT): the gateway emits the literal
		// "true"/"false" via strconv.FormatBool, and the kyc service gates on an
		// exact "true" match (kyc internal/platform/middleware/identity.go).
		// Neither side may drift to a different encoding (JSON bool / "1" / "True")
		// without breaking the email-verified gate.
		c.Request.Header.Set("X-Email-Verified", strconv.FormatBool(claims.EmailVerified))

		// Pin the gateway-validated X-Request-ID onto the REQUEST header so the value
		// signed over is exactly the value the proxy forwards downstream (proxy.go reads
		// req.In.Header.Get("X-Request-ID")). RequestID() only writes the id to context
		// + the response header, so without this pinning an inbound request with a
		// missing/invalid client value would forward an EMPTY value while we signed over
		// the gateway-generated one — a guaranteed downstream mismatch.
		//
		// NOTE on trust scope: X-Request-ID is client-proposable within a safe pattern
		// (^[A-Za-z0-9_-]{1,64}$); invalid/empty values are replaced by a gateway-
		// generated UUID. It is a CORRELATION field, NOT an authorization input.
		// Downstream MUST NOT make authorization decisions based on X-Request-ID; its
		// presence in the canonical string exists only to bind the signature to a single
		// hop and prevent trivial replay — see CONVENTIONS §24.1.
		rid := c.GetString("request_id")
		c.Request.Header.Set("X-Request-ID", rid)

		// Step 3: sign the injected identity tuple (defense-in-depth, CONVENTIONS §24).
		// Skipped when no secret is configured (development only).
		if len(hmacSecret) == 0 {
			c.Next()

			return
		}

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		c.Request.Header.Set(headerGatewayTs, ts)

		// Determine bodyHashHex for the canonical string.
		//
		// For upload routes (large-body multipart POST — see uploadRoutes): use the
		// empty-body sentinel hex(sha256("")) and DO NOT read the body. The body
		// streams through untouched to the upstream.  The file service verifier uses
		// the same sentinel for the matching route, so both sides produce an identical
		// canonical string.
		//
		// For all other routes: read up to 1 MB, hash the real body, then restore it.
		// LimitReader caps at 1 MB (matching the downstream verifier's gatewayBodyLimit).
		// NOTE: the gateway router applies a 10 MiB bodyLimitMiddleware before this
		// middleware runs, so bodies arriving here are already capped at 10 MiB.
		const signerBodyLimit = 1 << 20 // 1 MB — matches verifier gatewayBodyLimit

		// emptyBodyHash is hex(SHA-256("")) — the sentinel used for upload routes on
		// both the gateway signer and the downstream verifier so the canonical string
		// is identical on both sides without reading the body.
		const emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

		var bodyHashHex string

		if isUploadRoute(c.Request.Method, c.Request.URL.Path) {
			// Upload route: skip body read, use empty-body sentinel.
			// Body streams through the proxy untouched.
			bodyHashHex = emptyBodyHash
		} else {
			// Non-upload route: read ≤1 MB, compute real body hash, restore body.
			var bodyBuf []byte

			if c.Request.Body != nil && c.Request.Body != http.NoBody {
				var readErr error

				bodyBuf, readErr = io.ReadAll(io.LimitReader(c.Request.Body, signerBodyLimit))
				if readErr != nil {
					// Body read failed — fail closed: return 502 rather than signing over
					// sha256("") which the downstream verifier would reject as a mismatch.
					// This is consistent with the verifier's own fail-closed posture.
					c.AbortWithStatus(http.StatusBadGateway)

					return
				}

				// Restore the body so the downstream proxy still receives it.
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyBuf))
			}

			bodyHashRaw := sha256.Sum256(bodyBuf)
			bodyHashHex = hex.EncodeToString(bodyHashRaw[:])
		}

		method := c.Request.Method

		// Compute the path field over EXACTLY the path the downstream will see (post
		// /api/<svc> prefix strip). The proxy strips the prefix before forwarding, so
		// the downstream verifier's URL.RequestURI() is the post-strip path.
		//
		// For routes already in their final form (/v1/me/*, /v1/auth/logout):
		// c.Param("svc") is empty, UpstreamPathForSigning returns the path unchanged.
		//
		// For /api/:svc/* routes: c.Param("svc") is the service name; strip /api/<svc>.
		//
		// For routes registered without the /:svc/ param (e.g. the SSE stream route
		// /api/chat/v1/messages/stream), the upstream middleware sets "svc" via c.Set
		// so that InjectIdentity still strips the correct prefix and the downstream
		// verifier receives a matching signed path.
		//
		// UpstreamPathForSigning also normalises the path (path.Clean), which matches
		// the proxy's own normalisation — preserving the invariant that signer and
		// forwarder see the same cleaned path.
		//
		// Preserve the query string (downstream verifier uses URL.RequestURI() =
		// path + "?" + rawQuery).
		rawPath := c.Request.URL.Path
		// Prefer the gin-context "svc" key (set by SSEAuth on routes without /:svc/)
		// over the URL path param, falling back to c.Param for the normal /api/:svc/* case.
		svcRaw, _ := c.Get("svc")
		svcStr, _ := svcRaw.(string)
		if svcStr == "" {
			svcStr = c.Param("svc")
		}

		var signingPath string
		if svcStr != "" {
			stripped, valid := proxy.UpstreamPathForSigning(rawPath, svcStr)
			if !valid {
				// Path contained null bytes / CRLF — already blocked by the proxy guard,
				// but be defensive here too.
				c.AbortWithStatus(http.StatusBadRequest)

				return
			}

			signingPath = stripped
		} else {
			signingPath = rawPath
		}

		// Re-attach the raw query string so the path field matches URL.RequestURI()
		// on the downstream side.
		if q := c.Request.URL.RawQuery; q != "" {
			signingPath += "?" + q
		}

		path := signingPath

		canonical := fmt.Sprintf(
			"%d\n%s\n%d\n%s\n%d\n%s\n%s",
			len(method), method,
			len(path), path,
			len(bodyHashHex), bodyHashHex,
			strings.Join([]string{
				c.Request.Header.Get("X-User-Id"),
				c.Request.Header.Get("X-Kyc-Tier"),
				c.Request.Header.Get("X-Account-Type"),
				c.Request.Header.Get("X-Email-Verified"),
				rid,
				ts,
			}, "|"),
		)

		mac := hmac.New(sha256.New, hmacSecret)
		_, _ = mac.Write([]byte(canonical)) // hmac.Hash.Write never returns an error
		c.Request.Header.Set(headerGatewaySignature, hex.EncodeToString(mac.Sum(nil)))

		c.Next()
	}
}
