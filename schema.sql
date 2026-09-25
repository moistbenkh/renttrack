-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- USERS (landlords + tenants share this table via role column)
-- ============================================================
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    full_name       VARCHAR(255) NOT NULL,
    role            VARCHAR(20) NOT NULL CHECK (role IN ('landlord', 'tenant')),
    phone           VARCHAR(20),
    avatar_url      TEXT,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- REFRESH TOKENS (for secure token rotation)
-- ============================================================
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token       TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- PROPERTIES (owned by a landlord)
-- ============================================================
CREATE TABLE properties (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    landlord_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    address      TEXT NOT NULL,
    city         VARCHAR(100),
    image_url    TEXT,
    description  TEXT,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- UNITS (belong to a property)
-- ============================================================
CREATE TABLE units (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id  UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
    unit_number  VARCHAR(50) NOT NULL,
    rent_amount  DECIMAL(12,2) NOT NULL CHECK (rent_amount >= 0),
    bedrooms     INT DEFAULT 1 CHECK (bedrooms >= 0),
    bathrooms    INT DEFAULT 1 CHECK (bathrooms >= 0),
    is_occupied  BOOLEAN DEFAULT FALSE,
    description  TEXT,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(property_id, unit_number)
);

-- ============================================================
-- LEASES (links a tenant to a unit)
-- ============================================================
CREATE TABLE leases (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    unit_id      UUID NOT NULL REFERENCES units(id) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL REFERENCES users(id),
    landlord_id  UUID NOT NULL REFERENCES users(id),
    start_date   DATE NOT NULL,
    end_date     DATE,
    rent_amount  DECIMAL(12,2) NOT NULL CHECK (rent_amount >= 0),
    due_day      INT NOT NULL DEFAULT 1 CHECK (due_day BETWEEN 1 AND 28),
    is_active    BOOLEAN DEFAULT TRUE,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- AUDIT LOG (append-only — nobody can UPDATE or DELETE this)
-- ============================================================
CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id),
    action      VARCHAR(100) NOT NULL,
    table_name  VARCHAR(50),
    record_id   UUID,
    details     JSONB,
    ip_address  VARCHAR(45),
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Revoke UPDATE and DELETE on audit_log for the app user
-- Run this after CREATE: REVOKE UPDATE, DELETE ON audit_log FROM your_db_user;

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX idx_properties_landlord  ON properties(landlord_id);
CREATE INDEX idx_units_property       ON units(property_id);
CREATE INDEX idx_leases_unit          ON leases(unit_id);
CREATE INDEX idx_leases_tenant        ON leases(tenant_id);
CREATE INDEX idx_leases_landlord      ON leases(landlord_id);
CREATE INDEX idx_refresh_tokens_user  ON refresh_tokens(user_id);
CREATE INDEX idx_audit_user           ON audit_log(user_id);
CREATE INDEX idx_audit_created        ON audit_log(created_at DESC);
