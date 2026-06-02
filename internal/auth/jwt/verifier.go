package jwt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// KeyResolver resolves a kid string to an ed25519.PublicKey.
// Returning (nil, nil) causes verification to fail with UNAUTHORIZED.
type KeyResolver interface {
	Get(kid string) (ed25519.PublicKey, error)
}

// Verifier validates EdDSA JWT tokens using keys from a KeyResolver.
// It enforces alg=EdDSA exclusively and validates standard claims.
type Verifier struct {
	resolver  KeyResolver
	issuer    string
	audience  string
	leewaySec int
}

// NewVerifier creates a Verifier with the given KeyResolver and claim expectations.
func NewVerifier(resolver KeyResolver, issuer, audience string, leewaySec int) *Verifier {
	return &Verifier{
		resolver:  resolver,
		issuer:    issuer,
		audience:  audience,
		leewaySec: leewaySec,
	}
}

// Verify parses and validates a JWT string, returning the embedded Claims.
// Rejects all non-EdDSA algorithms including alg=none, HS256, RS256, etc.
func (v *Verifier) Verify(tokenStr string) (*Claims, error) {
	leeway := time.Duration(v.leewaySec) * time.Second

	token, err := gojwt.ParseWithClaims(
		tokenStr, &Claims{},
		v.keyfunc,
		gojwt.WithValidMethods([]string{"EdDSA"}),
		gojwt.WithLeeway(leeway),
		gojwt.WithIssuedAt(),
		gojwt.WithIssuer(v.issuer),
		gojwt.WithAudience(v.audience),
		gojwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid jwt claims")
	}

	return claims, nil
}

// keyfunc retrieves the Ed25519 public key for the given token's kid header.
// Belt-and-suspenders: also type-asserts that the signing method is *gojwt.SigningMethodEd25519
// in addition to WithValidMethods, to close the HS256-with-public-key alg-confusion attack.
func (v *Verifier) keyfunc(token *gojwt.Token) (any, error) {
	// Alg-confusion guard: assert the token uses EdDSA (Ed25519).
	if _, ok := token.Method.(*gojwt.SigningMethodEd25519); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, errors.New("missing kid header")
	}

	pub, err := v.resolver.Get(kid)
	if err != nil {
		return nil, fmt.Errorf("key lookup for kid %q: %w", kid, err)
	}

	if pub == nil {
		return nil, fmt.Errorf("unknown kid: %q", kid)
	}

	return pub, nil
}
