package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/Anvoria/authly/internal/utils"
)

const (
	// IdentityKey is the key used to store the identity in Fiber context
	IdentityKey = "identity"
)

// AuthMiddleware verifies the access token
func AuthMiddleware(keyStore *KeyStore, svc AuthService, issuer string, expectedAudience []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return utils.ErrorResponse(c, "missing_authorization_header", fiber.StatusUnauthorized)
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return utils.ErrorResponse(c, "invalid_authorization_header", fiber.StatusUnauthorized)
		}

		token := parts[1]
		if token == "" {
			return utils.ErrorResponse(c, "missing_token", fiber.StatusUnauthorized)
		}

		claims, err := keyStore.Verify(token)
		if err != nil {
			return utils.ErrorResponse(c, "invalid_token", fiber.StatusUnauthorized)
		}

		if err := claims.Validate(issuer, expectedAudience); err != nil {
			return utils.ErrorResponse(c, "token_expired_or_invalid", fiber.StatusUnauthorized)
		}

		revoked, err := svc.IsTokenRevoked(claims)
		if err != nil {
			return utils.ErrorResponse(c, "token_validation_error", fiber.StatusInternalServerError)
		}
		if revoked {
			return utils.ErrorResponse(c, "token_revoked", fiber.StatusUnauthorized)
		}

		identity := &Identity{
			UserID:      claims.Subject(),
			SessionID:   claims.GetSid(),
			PermissionV: claims.GetPermissionV(),
		}

		c.Locals(IdentityKey, identity)

		return c.Next()
	}
}

// GetIdentity extracts the identity from Fiber context
func GetIdentity(c *fiber.Ctx) *Identity {
	identity, ok := c.Locals(IdentityKey).(*Identity)
	if !ok {
		return nil
	}
	return identity
}
