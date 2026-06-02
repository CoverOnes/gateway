package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// JWKSKey represents a single JSON Web Key for Ed25519 public keys.
// Copied from user service (CONVENTIONS §18).
type JWKSKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"` // base64url raw public key bytes
}

// JWKS is the JSON Web Key Set published at /jwks by the user service.
type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

// ParsePublicKey decodes a JWKSKey into an ed25519.PublicKey.
// Validates kty=OKP, crv=Ed25519, alg=EdDSA and correct key length.
// The key is passed by pointer to avoid copying the 96-byte struct (gocritic hugeParam).
func ParsePublicKey(key *JWKSKey) (ed25519.PublicKey, error) {
	if key.Kty != "OKP" {
		return nil, fmt.Errorf("unsupported kty %q, expected OKP", key.Kty)
	}

	if key.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported crv %q, expected Ed25519", key.Crv)
	}

	if key.Alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported alg %q, expected EdDSA", key.Alg)
	}

	pub, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("x must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}

	return ed25519.PublicKey(pub), nil
}
