package user

import (
	"testing"

	"github.com/Anvoria/authly/internal/utils"
	"gorm.io/gorm"
)

// setupTestDB creates a PostgreSQL database connection for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db := utils.SetupTestDB(t, &User{})
	db.Exec("DELETE FROM users")
	return db
}

func TestService_Register(t *testing.T) {
	db := setupTestDB(t)
	repo := NewRepository(db)
	service := NewService(repo)

	tests := []struct {
		name    string
		req     RegisterRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful registration",
			req: RegisterRequest{
				Username:  "testuser",
				Email:     "test@example.com",
				Password:  "securepassword123",
				FirstName: "Test",
				LastName:  "User",
			},
			wantErr: false,
		},
		{
			name: "duplicate email",
			req: RegisterRequest{
				Username:  "testuser2",
				Email:     "test@example.com",
				Password:  "securepassword123",
				FirstName: "Test",
				LastName:  "User",
			},
			wantErr: true,
			errMsg:  "email already exists",
		},
		{
			name: "duplicate username",
			req: RegisterRequest{
				Username:  "testuser",
				Email:     "different@example.com",
				Password:  "securepassword123",
				FirstName: "Test",
				LastName:  "User",
			},
			wantErr: true,
			errMsg:  "username already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db.Exec("DELETE FROM users")

			if tt.wantErr {
				switch tt.errMsg {
				case "email already exists":
					_, err := service.Register(RegisterRequest{
						Username:  "existinguser",
						Email:     tt.req.Email,
						Password:  "password123",
						FirstName: "Existing",
						LastName:  "User",
					})
					if err != nil {
						t.Fatalf("Failed to create existing user for duplicate email test: %v", err)
					}
				case "username already exists":
					_, err := service.Register(RegisterRequest{
						Username:  tt.req.Username,
						Email:     "existing@example.com",
						Password:  "password123",
						FirstName: "Existing",
						LastName:  "User",
					})
					if err != nil {
						t.Fatalf("Failed to create existing user for duplicate username test: %v", err)
					}
				}
			}

			user, err := service.Register(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Register() expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("Register() error = %v, want %v", err.Error(), tt.errMsg)
				}
				if user != nil {
					t.Errorf("Register() expected nil user on error, got %v", user)
				}
			} else {
				if err != nil {
					t.Errorf("Register() unexpected error: %v", err)
					return
				}
				if user == nil {
					t.Errorf("Register() expected user but got nil")
					return
				}

				if user.Username != tt.req.Username {
					t.Errorf("Register() username = %v, want %v", user.Username, tt.req.Username)
				}
				if user.Email != tt.req.Email {
					t.Errorf("Register() email = %v, want %v", user.Email, tt.req.Email)
				}
				if user.FirstName != tt.req.FirstName {
					t.Errorf("Register() firstName = %v, want %v", user.FirstName, tt.req.FirstName)
				}
				if user.LastName != tt.req.LastName {
					t.Errorf("Register() lastName = %v, want %v", user.LastName, tt.req.LastName)
				}
				if user.Password == "" {
					t.Errorf("Register() password should be hashed, got empty string")
				}
				if user.Password == tt.req.Password {
					t.Errorf("Register() password should be hashed, got plain text")
				}
				if !user.IsActive {
					t.Errorf("Register() isActive = false, want true")
				}

				if !service.VerifyPassword(user, tt.req.Password) {
					t.Errorf("VerifyPassword() failed for registered user")
				}

				if service.VerifyPassword(user, "wrongpassword") {
					t.Errorf("VerifyPassword() should fail for wrong password")
				}
			}
		})
	}
}

func TestService_VerifyPassword(t *testing.T) {
	db := setupTestDB(t)
	repo := NewRepository(db)
	service := NewService(repo)

	req := RegisterRequest{
		Username:  "verifyuser",
		Email:     "verify@example.com",
		Password:  "correctpassword",
		FirstName: "Test",
		LastName:  "User",
	}

	user, err := service.Register(req)
	if err != nil {
		t.Fatalf("Failed to register user for password verification test: %v", err)
	}

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "correct password",
			password: "correctpassword",
			want:     true,
		},
		{
			name:     "wrong password",
			password: "wrongpassword",
			want:     false,
		},
		{
			name:     "empty password",
			password: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.VerifyPassword(user, tt.password)
			if got != tt.want {
				t.Errorf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
