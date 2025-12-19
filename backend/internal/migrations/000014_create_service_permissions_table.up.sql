CREATE TABLE service_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    client_id VARCHAR(255) NOT NULL,
    target_service_id UUID NOT NULL,
    resource TEXT,
    bitmask NUMERIC(20) DEFAULT 0,
    CONSTRAINT fk_service_permissions_client FOREIGN KEY (client_id) REFERENCES services(client_id) ON DELETE CASCADE,
    CONSTRAINT fk_service_permissions_target FOREIGN KEY (target_service_id) REFERENCES services(id) ON DELETE CASCADE,
    UNIQUE(client_id, target_service_id, resource)
);

CREATE INDEX idx_service_permissions_client_id ON service_permissions(client_id);
