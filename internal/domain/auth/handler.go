package auth

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/Anvoria/authly/internal/utils"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Handler struct {
	Service *Service
}

func NewHandler(s *Service) *Handler {
	return &Handler{Service: s}
}

func (h *Handler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, "invalid_body", fiber.StatusBadRequest)
	}

	res, err := h.Service.Login(req.Email, req.Password, c.Get("User-Agent"), c.IP(), 24*time.Hour)
	if err != nil {
		return utils.ErrorResponse(c, err.Error(), fiber.StatusUnauthorized)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    res.RefreshToken,
		HTTPOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: "None",
	})

	return utils.SuccessResponse(c, res, "Login successful")
}
