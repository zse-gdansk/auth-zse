package utils

import "github.com/gofiber/fiber/v2"

// APIError represents a structured API error
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
	Details any    `json:"details,omitempty"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return e.Message
}

// NewAPIError creates a new APIError
func NewAPIError(code, message string, status int) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Status:  status,
	}
}

// Common API Errors
var (
	ErrInternalServer = NewAPIError("INTERNAL_SERVER_ERROR", "An unexpected error occurred", fiber.StatusInternalServerError)
	ErrBadRequest     = NewAPIError("BAD_REQUEST", "Invalid request", fiber.StatusBadRequest)
	ErrUnauthorized   = NewAPIError("UNAUTHORIZED", "Authentication required", fiber.StatusUnauthorized)
	ErrForbidden      = NewAPIError("FORBIDDEN", "You do not have permission to access this resource", fiber.StatusForbidden)
	ErrNotFound       = NewAPIError("NOT_FOUND", "Resource not found", fiber.StatusNotFound)
)
