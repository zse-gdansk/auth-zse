package utils

import (
	"github.com/gofiber/fiber/v2"
)

// SuccessResponse sends a success JSON response
func SuccessResponse(c *fiber.Ctx, data any, message string, code ...int) error {
	statusCode := fiber.StatusOK
	if len(code) > 0 {
		statusCode = code[0]
	}

	return c.Status(statusCode).JSON(fiber.Map{
		"success": true,
		"data":    data,
		"message": message,
	})
}

// ErrorResponse sends an error JSON response.
// It accepts a string, error, or APIError.
func ErrorResponse(c *fiber.Ctx, err any, code ...int) error {
	var apiError *APIError

	switch e := err.(type) {
	case *APIError:
		apiError = e
	case error:
		apiError = &APIError{
			Code:    "UNKNOWN_ERROR",
			Message: e.Error(),
			Status:  fiber.StatusInternalServerError,
		}
	case string:
		apiError = &APIError{
			Code:    "ERROR",
			Message: e,
			Status:  fiber.StatusInternalServerError,
		}
	default:
		apiError = ErrInternalServer
	}

	// Override status code if provided
	if len(code) > 0 {
		apiError.Status = code[0]
	}

	// If the status is still 0 (default int), set it to 500
	if apiError.Status == 0 {
		apiError.Status = fiber.StatusInternalServerError
	}

	return c.Status(apiError.Status).JSON(fiber.Map{
		"success": false,
		"error":   apiError,
	})
}

// OIDCErrorResponse sends an OpenID Connect error response as JSON.
// It sets the HTTP status to 400 (Bad Request) unless an explicit status code
// is provided via the optional variadic `code` argument. The JSON body contains
// the keys "error" and "error_description" with the provided values.
// It returns any error encountered while writing the response.
func OIDCErrorResponse(c *fiber.Ctx, message, errorDescription string, code ...int) error {
	statusCode := fiber.StatusBadRequest
	if len(code) > 0 {
		statusCode = code[0]
	}

	return c.Status(statusCode).JSON(fiber.Map{
		"error":             message,
		"error_description": errorDescription,
	})
}
