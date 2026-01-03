package utils

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestErrorResponse_NoMutation(t *testing.T) {
	app := fiber.New()

	// Initial status should be 500
	assert.Equal(t, fiber.StatusInternalServerError, ErrInternalServer.Status)

	// Call ErrorResponse with an override
	app.Get("/error", func(c *fiber.Ctx) error {
		return ErrorResponse(c, ErrInternalServer, fiber.StatusTeapot)
	})

	req := httptest.NewRequest("GET", "/error", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusTeapot, resp.StatusCode)

	// Check if shared instance was mutated
	assert.Equal(t, fiber.StatusInternalServerError, ErrInternalServer.Status, "ErrInternalServer.Status should NOT be mutated")

	// Verify JSON body
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Success bool     `json:"success"`
		Error   APIError `json:"error"`
	}
	err = json.Unmarshal(body, &result)
	assert.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, ErrInternalServer.Code, result.Error.Code)
}

func TestErrorResponse_PointerNoMutation(t *testing.T) {
	app := fiber.New()

	customErr := NewAPIError("CUSTOM", "Custom message", fiber.StatusNotFound)

	app.Get("/custom", func(c *fiber.Ctx) error {
		return ErrorResponse(c, customErr, fiber.StatusConflict)
	})

	req := httptest.NewRequest("GET", "/custom", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusConflict, resp.StatusCode)

	// Original customErr should still have StatusNotFound
	assert.Equal(t, fiber.StatusNotFound, customErr.Status, "Original APIError should NOT be mutated")
}
