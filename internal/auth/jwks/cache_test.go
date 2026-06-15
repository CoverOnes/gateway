package jwks_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CoverOnes/gateway/internal/auth/jwks"
	authjwt "github.com/CoverOnes/gateway/internal/auth/jwt"
)

// generateKey creates an Ed25519 key pair and returns the public key, kid, and base64url-encoded x.
func generateKey(t *testing.T) (pub ed25519.PublicKey, kid, x string) {
	t.Helper()

	pubBytes, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	xVal := base64.RawURLEncoding.EncodeToString(pubBytes)
	kidVal := "test-" + xVal[:8]

	return pubBytes, kidVal, xVal
}

func serveJWKS(t *testing.T, keys []authjwt.JWKSKey) *httptest.Server {
	t.Helper()

	jwksPayload, err := json.Marshal(authjwt.JWKS{Keys: keys})
	require.NoError(t, err)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksPayload)
	}))
}

func TestCache_FetchAndParse(t *testing.T) {
	pub, kid, x := generateKey(t)

	srv := serveJWKS(t, []authjwt.JWKSKey{
		{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid, X: x},
	})
	defer srv.Close()

	cache := jwks.NewCache(srv.URL, 5*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	assert.True(t, cache.Ready(), "cache should be ready after successful fetch")

	got, err := cache.Get(kid)
	require.NoError(t, err)
	assert.Equal(t, pub, got)
}

func TestCache_FailSecure_KeepsLastGoodKeys(t *testing.T) {
	pub, kid, x := generateKey(t)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++

		if callCount == 1 {
			// First call: return valid JWKS.
			jwksPayload, err := json.Marshal(authjwt.JWKS{Keys: []authjwt.JWKSKey{
				{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid, X: x},
			}})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(jwksPayload)
		} else {
			// Subsequent calls: simulate upstream down.
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	cache := jwks.NewCache(srv.URL, 50*time.Millisecond, 5*time.Second)
	cache.Start(context.Background())

	// Cache is populated from first fetch.
	assert.True(t, cache.Ready())

	// Wait for background refresh to fire and fail.
	time.Sleep(200 * time.Millisecond)

	// Keys from first fetch should still be available (fail-secure).
	assert.True(t, cache.Ready())

	got, err := cache.Get(kid)
	require.NoError(t, err)
	assert.Equal(t, pub, got)
}

func TestCache_RefreshOnUnknownKid(t *testing.T) {
	_, kid1, x1 := generateKey(t)
	pub2, kid2, x2 := generateKey(t)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++

		var keys []authjwt.JWKSKey
		if callCount == 1 {
			// First fetch: only kid1.
			keys = []authjwt.JWKSKey{
				{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid1, X: x1},
			}
		} else {
			// After rotation: kid1 + kid2.
			keys = []authjwt.JWKSKey{
				{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid1, X: x1},
				{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid2, X: x2},
			}
		}

		payload, err := json.Marshal(authjwt.JWKS{Keys: keys})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	cache := jwks.NewCache(srv.URL, 10*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	// kid2 is not in cache yet — Get triggers single-flight refresh.
	got, err := cache.Get(kid2)
	require.NoError(t, err)
	assert.Equal(t, pub2, got)
	assert.GreaterOrEqual(t, callCount, 2, "should have triggered a refresh fetch")
}

func TestCache_RejectMalformedX(t *testing.T) {
	srv := serveJWKS(t, []authjwt.JWKSKey{
		{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: "bad-key", X: "not-valid-base64!!!"},
	})
	defer srv.Close()

	// Serving only a malformed key should leave the cache empty (not_ready).
	cache := jwks.NewCache(srv.URL, 5*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	// Cache should NOT be ready since no valid keys were loaded.
	assert.False(t, cache.Ready(), "cache should not be ready when all keys are malformed")
}

func TestCache_InitialFetchFails_NotReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := jwks.NewCache(srv.URL, 5*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	assert.False(t, cache.Ready(), "cache should not be ready when initial fetch fails")
}

func TestCache_UnknownKidAfterRefreshReturnsNil(t *testing.T) {
	_, kid1, x1 := generateKey(t)

	srv := serveJWKS(t, []authjwt.JWKSKey{
		{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid1, X: x1},
	})
	defer srv.Close()

	cache := jwks.NewCache(srv.URL, 10*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	// Request a kid that does not exist even after refresh.
	got, err := cache.Get("nonexistent-kid")
	require.NoError(t, err)
	assert.Nil(t, got, "unknown kid should return nil after re-fetch")
}

// TestCache_CrossHostRedirectIsRejected verifies that a JWKS endpoint that issues
// a 302 redirect to a different host is refused. This guards against SSRF via a
// compromised/misconfigured JWKS server that redirects to a cloud-metadata service
// (e.g. 169.254.169.254) or any other cross-host destination.
func TestCache_CrossHostRedirectIsRejected(t *testing.T) {
	// Forbidden target: any host that differs from the original JWKS server.
	// We use a second httptest server as the "forbidden" redirect destination.
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// This handler must never be reached; if it is, the test fails below.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer forbidden.Close()

	// JWKS server that always issues a 302 to the forbidden host.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, forbidden.URL+"/jwks", http.StatusFound)
	}))
	defer redirector.Close()

	cache := jwks.NewCache(redirector.URL, 5*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	// The redirect to a different host must be rejected; the cache must NOT be ready.
	assert.False(t, cache.Ready(),
		"cache must not be ready when JWKS endpoint redirects to a cross-host destination")
}

// TestCache_SameHostRedirectIsAllowed verifies that a JWKS server issuing a
// same-host redirect (e.g. HTTP→HTTPS upgrade or path normalization) is followed.
func TestCache_SameHostRedirectIsAllowed(t *testing.T) {
	_, kid, x := generateKey(t)

	// We need a test server that responds to two paths on the same host:
	// GET / → 302 to /jwks (same host)
	// GET /jwks → real JWKS
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jwks", http.StatusFound)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		payload, err := json.Marshal(authjwt.JWKS{Keys: []authjwt.JWKSKey{
			{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid, X: x},
		}})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Point cache at the root path which redirects to /jwks on the same host.
	cache := jwks.NewCache(srv.URL+"/", 5*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	assert.True(t, cache.Ready(),
		"cache must be ready after following a same-host redirect")
}

// TestCache_SingleFlightReusesLeaderFetch verifies that when many goroutines
// concurrently look up the same unknown kid, only the single-flight leader
// performs an upstream GET; the woken waiters re-check the cache and reuse the
// key the leader just fetched instead of issuing redundant fetches.
func TestCache_SingleFlightReusesLeaderFetch(t *testing.T) {
	_, kid1, x1 := generateKey(t)
	pub2, kid2, x2 := generateKey(t)

	var fetchCount int32

	// release blocks the FIRST refresh fetch until all goroutines are parked on
	// the single-flight condition, so they genuinely contend for the leader slot.
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&fetchCount, 1)

		var keys []authjwt.JWKSKey
		if n == 1 {
			// Initial fetch: only kid1 is known.
			keys = []authjwt.JWKSKey{
				{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid1, X: x1},
			}
		} else {
			// First refresh (the leader): hold until the waiters are parked,
			// then return kid1 + kid2.
			if n == 2 {
				<-release
			}

			keys = []authjwt.JWKSKey{
				{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid1, X: x1},
				{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: kid2, X: x2},
			}
		}

		payload, err := json.Marshal(authjwt.JWKS{Keys: keys})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	cache := jwks.NewCache(srv.URL, 10*time.Minute, 5*time.Second)
	cache.Start(context.Background())

	require.True(t, cache.Ready())
	require.Equal(t, int32(1), atomic.LoadInt32(&fetchCount), "initial fetch only")

	const concurrent = 12

	var (
		wg      sync.WaitGroup
		results = make([]ed25519.PublicKey, concurrent)
		errs    = make([]error, concurrent)
	)

	wg.Add(concurrent)

	for i := range concurrent {
		go func(idx int) {
			defer wg.Done()

			got, err := cache.Get(kid2)
			results[idx] = got
			errs[idx] = err
		}(i)
	}

	// Give the goroutines time to all park on the single-flight condition behind
	// the leader, then let the leader's fetch complete.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	// Every concurrent caller must observe the leader's freshly fetched key.
	for i := range concurrent {
		require.NoErrorf(t, errs[i], "goroutine %d", i)
		assert.Equalf(t, pub2, results[i], "goroutine %d should see leader-fetched kid2", i)
	}

	// Exactly one refresh fetch (total 2: initial + single leader refresh).
	// Without the re-check, woken waiters would each issue their own GET.
	assert.Equal(t, int32(2), atomic.LoadInt32(&fetchCount),
		"single-flight must collapse concurrent unknown-kid lookups into one upstream fetch")
}
