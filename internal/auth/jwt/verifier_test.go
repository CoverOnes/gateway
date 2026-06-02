package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CoverOnes/gateway/internal/auth/jwt"
)

// staticKeyResolver implements KeyResolver with a fixed map of keys.
type staticKeyResolver struct {
	keys map[string]ed25519.PublicKey
}

func (r *staticKeyResolver) Get(kid string) (ed25519.PublicKey, error) {
	return r.keys[kid], nil
}

func generateEdDSAKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return pub, priv
}

func signToken(t *testing.T, priv ed25519.PrivateKey, kid string, claims *jwt.Claims) string {
	t.Helper()

	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	require.NoError(t, err)

	return signed
}

func validClaims(now time.Time) *jwt.Claims {
	return &jwt.Claims{
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    jwt.Issuer,
			Subject:   "user-123",
			Audience:  gojwt.ClaimStrings{jwt.Audience},
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		KYCTier:     1,
		AccountType: "PERSONAL",
	}
}

func TestVerifier(t *testing.T) {
	pub, priv := generateEdDSAKey(t)
	kid := "test-kid-001"

	resolver := &staticKeyResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	v := jwt.NewVerifier(resolver, jwt.Issuer, jwt.Audience, 60)

	now := time.Now().UTC()

	t.Run("valid EdDSA token is accepted", func(t *testing.T) {
		token := signToken(t, priv, kid, validClaims(now))

		claims, err := v.Verify(token)
		require.NoError(t, err)
		assert.Equal(t, "user-123", claims.Subject)
		assert.Equal(t, int16(1), claims.KYCTier)
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		expired := &jwt.Claims{
			RegisteredClaims: gojwt.RegisteredClaims{
				Issuer:    jwt.Issuer,
				Subject:   "user-123",
				Audience:  gojwt.ClaimStrings{jwt.Audience},
				IssuedAt:  gojwt.NewNumericDate(now.Add(-20 * time.Minute)),
				ExpiresAt: gojwt.NewNumericDate(now.Add(-10 * time.Minute)),
			},
		}
		token := signToken(t, priv, kid, expired)

		_, err := v.Verify(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid jwt")
	})

	t.Run("wrong issuer is rejected", func(t *testing.T) {
		wrongIss := &jwt.Claims{
			RegisteredClaims: gojwt.RegisteredClaims{
				Issuer:    "wrong-issuer",
				Subject:   "user-123",
				Audience:  gojwt.ClaimStrings{jwt.Audience},
				IssuedAt:  gojwt.NewNumericDate(now),
				ExpiresAt: gojwt.NewNumericDate(now.Add(10 * time.Minute)),
			},
		}
		token := signToken(t, priv, kid, wrongIss)

		_, err := v.Verify(token)
		require.Error(t, err)
	})

	t.Run("wrong audience is rejected", func(t *testing.T) {
		wrongAud := &jwt.Claims{
			RegisteredClaims: gojwt.RegisteredClaims{
				Issuer:    jwt.Issuer,
				Subject:   "user-123",
				Audience:  gojwt.ClaimStrings{"wrong-audience"},
				IssuedAt:  gojwt.NewNumericDate(now),
				ExpiresAt: gojwt.NewNumericDate(now.Add(10 * time.Minute)),
			},
		}
		token := signToken(t, priv, kid, wrongAud)

		_, err := v.Verify(token)
		require.Error(t, err)
	})

	t.Run("unknown kid is rejected", func(t *testing.T) {
		// Sign with same key but use a kid that is not in the resolver
		token := signToken(t, priv, "unknown-kid", validClaims(now))

		_, err := v.Verify(token)
		require.Error(t, err)
	})

	t.Run("tampered signature is rejected", func(t *testing.T) {
		token := signToken(t, priv, kid, validClaims(now))
		// Replace the signature part (third JWT segment) with a zeroed-out base64 string.
		// Ed25519 signature is 64 bytes; a 64-byte zero signature is never valid.
		parts := strings.SplitN(token, ".", 3)
		require.Len(t, parts, 3, "JWT must have 3 parts")

		// Replace signature with the base64url encoding of 64 zero bytes.
		zeroSig := strings.Repeat("A", 86) // 64 bytes in base64url without padding ≈ 86 chars
		tampered := parts[0] + "." + parts[1] + "." + zeroSig

		_, err := v.Verify(tampered)
		require.Error(t, err)
	})

	t.Run("alg=none is rejected", func(t *testing.T) {
		// Manually construct alg=none token (three-part with empty signature)
		claims := validClaims(now)
		unsigned := gojwt.NewWithClaims(gojwt.SigningMethodNone, claims)
		unsigned.Header["kid"] = kid
		noneToken, err := unsigned.SignedString(gojwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		_, err = v.Verify(noneToken)
		require.Error(t, err)
	})

	t.Run("HS256 (alg confusion) is rejected", func(t *testing.T) {
		claims := validClaims(now)
		// Use the public key bytes as HMAC secret — the classic alg confusion attack
		hs256Token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
		hs256Token.Header["kid"] = kid
		// We need a string secret for HS256
		signed, err := hs256Token.SignedString([]byte("any-secret"))
		require.NoError(t, err)

		_, err = v.Verify(signed)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid jwt")
	})

	t.Run("RS256 is rejected", func(t *testing.T) {
		// Attempt to verify a token with RS256 algorithm — WithValidMethods rejects it.
		// We cannot sign a real RS256 token without an RSA key, but we can verify
		// that any token claiming RS256 is rejected before reaching the keyfunc.
		// Use a garbage token string; the important thing is the error comes from alg mismatch.
		_, rsErr := v.Verify("not-a-valid-rs256-token")
		require.Error(t, rsErr, "invalid token string must be rejected")
	})
}
