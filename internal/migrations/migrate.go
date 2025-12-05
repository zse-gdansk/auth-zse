package migrations

import (
	"fmt"

	"github.com/Anvoria/authly/internal/domain/user"
	"gorm.io/gorm"
)

// RunMigrations runs all database migrations
func RunMigrations(db *gorm.DB) error {
	if err := db.AutoMigrate(&user.User{}); err != nil {
		return fmt.Errorf("failed to make migrations: %w", err)
	}
	return nil
}
