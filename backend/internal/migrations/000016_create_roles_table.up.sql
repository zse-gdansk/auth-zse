CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    bitmask NUMERIC(20) NOT NULL DEFAULT 0,
    is_default BOOLEAN NOT NULL DEFAULT false,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    CONSTRAINT fk_roles_services FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_roles_deleted_at ON roles(deleted_at);

CREATE INDEX IF NOT EXISTS idx_roles_service_id ON roles(service_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_service_name ON roles(service_id, name) WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_service_default ON roles(service_id) WHERE is_default = true AND deleted_at IS NULL;

ALTER TABLE user_permissions ADD COLUMN IF NOT EXISTS role_id UUID;

ALTER TABLE user_permissions 
    ADD CONSTRAINT fk_user_permissions_roles 
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_user_permissions_role_id ON user_permissions(role_id);
