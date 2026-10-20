-- ==============================================================================
-- TrustVault — Zero-Trust Document Sharing Platform
-- Production PostgreSQL Database Schema with Strict Relational Constraints & Indices
-- ==============================================================================

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(50),
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    otp_code VARCHAR(10),
    otp_expires_at TIMESTAMPTZ,
    is_2fa_enabled BOOLEAN DEFAULT FALSE,
    account_status VARCHAR(50) DEFAULT 'ACTIVE',
    admin_auth_code VARCHAR(50),
    terms_accepted BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- 2. Documents Table
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'Confidential',
    file_path VARCHAR(500) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_hash VARCHAR(64) NOT NULL, -- SHA-256 content checksum
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_documents_created ON documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(file_hash);

-- 3. Document Permissions Table
CREATE TABLE IF NOT EXISTS document_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_level VARCHAR(20) NOT NULL CHECK (access_level IN ('read', 'edit')),
    is_revoked BOOLEAN DEFAULT FALSE NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked_at TIMESTAMPTZ,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT uq_doc_user_grant UNIQUE (document_id, user_id)
);

-- Critical performance index for zero-trust authorization middleware
CREATE INDEX IF NOT EXISTS idx_doc_perm_lookup ON document_permissions(document_id, user_id, is_revoked);
CREATE INDEX IF NOT EXISTS idx_doc_perm_user ON document_permissions(user_id);

-- 4. Audit Logs Table (Append-Only & Cryptographically Chained)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255),
    action VARCHAR(50) NOT NULL, -- UPLOAD, READ_SUCCESS, READ_DENIED, REVOKE, DELETE, GRANT, EDIT
    target_resource VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('SUCCESS', 'DENIED')),
    details TEXT DEFAULT '{}',
    prev_hash VARCHAR(64) NOT NULL,
    entry_hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(target_resource);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);

-- ==============================================================================
-- Database-Level Immutability Enforcement
-- Prevents UPDATE or DELETE on audit_logs at the SQL engine layer.
-- ==============================================================================
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: audit_logs is an immutable append-only ledger. UPDATE and DELETE operations are strictly prohibited.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;

CREATE TRIGGER trg_audit_logs_immutable
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_tampering();
