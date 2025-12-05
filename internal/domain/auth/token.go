package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims are the claims for the access token
type AccessTokenClaims struct {
	Sub string `json:"sub"`
	Sid string `json:"sid"`
	jwt.RegisteredClaims
}

// TokenGenerator generates JWT tokens
type TokenGenerator struct {
	privateKey any
	issuer     string
	ttl        time.Duration
}

// NewTokenGenerator creates a new TokenGenerator
func NewTokenGenerator(pk any, issuer string, ttl time.Duration) *TokenGenerator {
	return &TokenGenerator{privateKey: pk, issuer: issuer, ttl: ttl}
}

// GenerateAccessToken generates a new access token
func (tg *TokenGenerator) GenerateAccessToken(userID, sessionID string) (string, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		Sub: userID,
		Sid: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tg.issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(tg.ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tg.privateKey)
}
