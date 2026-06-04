// Package jwt provides JWT claim types and constants for the gateway service.
// Claims and issuer/audience constants are copied verbatim from the user service
// (github.com/CoverOnes/user/internal/auth/jwt) per CONVENTIONS §18 (shared code policy).
package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

const (
	// Issuer is the expected iss claim issued by the user service.
	Issuer = "coverones-user"
	// Audience is the expected aud claim for CoverOnes services.
	Audience = "coverones"
)

// Claims are the custom JWT claims embedded in access tokens issued by the user service.
type Claims struct {
	jwt.RegisteredClaims

	// KYCTier is the user's current verification tier (0-3).
	KYCTier int16 `json:"kycTier"`

	// AccountType is PERSONAL or COMPANY.
	AccountType string `json:"accountType"`

	// EmailVerified reports whether the user has verified their email address
	// (auth Increment 1). Older tokens issued before this claim existed omit it;
	// JSON unmarshalling then leaves this at its zero value (false), which is the
	// fail-safe default the gateway relies on when injecting X-Email-Verified.
	EmailVerified bool `json:"email_verified"`

	// TokenVersion is intentionally NOT validated at the gateway layer.
	// Token revocation is enforced by refresh-token family invalidation at the
	// user service: when a refresh family is revoked, the user service rejects
	// all subsequent /refresh calls from that family, preventing new access tokens
	// from being issued. Existing short-lived access tokens carry the field for
	// informational purposes only; the gateway does not compare it against any store.
	TokenVersion int `json:"tokenVersion"`
}
