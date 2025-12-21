package role

import (
	"github.com/Anvoria/authly/internal/database"
	"github.com/google/uuid"
)

// Role represents a role within a service
type Role struct {
	database.BaseModel
	ServiceID   uuid.UUID `gorm:"column:service_id;type:uuid;not null;index"`
	Name        string    `gorm:"column:name;type:varchar(255);not null"`
	Description string    `gorm:"column:description;type:text"`
	Bitmask     uint64    `gorm:"column:bitmask;type:numeric(20);not null;default:0"`
	IsDefault   bool      `gorm:"column:is_default;type:boolean;not null;default:false"`
	Priority    int       `gorm:"column:priority;type:integer;not null;default:0"`
}

// TableName returns the table name for Gorm
func (Role) TableName() string {
	return "roles"
}
