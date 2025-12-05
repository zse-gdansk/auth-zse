package auth

import (
	"errors"
	"time"

	"github.com/Anvoria/authly/internal/domain/session"
	"github.com/Anvoria/authly/internal/domain/user"
	"github.com/google/uuid"
)

var (
	// ErrInvalidCredentials is returned when email or password is incorrect
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// LoginResponse represents the response from a successful login
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Service handles authentication operations
type Service struct {
	Users    user.Repository
	Sessions session.Service
	Tokens   *TokenGenerator
}

// NewService creates a new auth service
func NewService(users user.Repository, sessions session.Service, tokens *TokenGenerator) *Service {
	return &Service{
		Users:    users,
		Sessions: sessions,
		Tokens:   tokens,
	}
}

// Login authenticates a user and creates a session
func (s *Service) Login(email, password, userAgent, ip string, ttl time.Duration) (*LoginResponse, error) {
	u, err := s.Users.GetByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !s.Users.VerifyPassword(u, password) {
		return nil, ErrInvalidCredentials
	}

	userID, err := uuid.Parse(u.ID.String())
	if err != nil {
		return nil, err
	}

	sessionID, secret, err := s.Sessions.Create(userID, userAgent, ip, ttl)
	if err != nil {
		return nil, err
	}

	access, err := s.Tokens.GenerateAccessToken(u.ID.String(), sessionID.String())
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken:  access,
		RefreshToken: sessionID.String() + ":" + secret,
	}, nil
}
