const fs = require('fs');
const path = require('path');
const { getDb, getDbType } = require('../config/database');

const postgresSchema = `
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

CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'Confidential',
    file_path VARCHAR(500) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_documents_created ON documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(file_hash);

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

CREATE INDEX IF NOT EXISTS idx_doc_perm_lookup ON document_permissions(document_id, user_id, is_revoked);
CREATE INDEX IF NOT EXISTS idx_doc_perm_user ON document_permissions(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255),
    action VARCHAR(50) NOT NULL,
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
`;

async function migrate() {
  const db = await getDb();
  const dbType = getDbType();
  console.log(`[Migration] Starting database migration for engine: ${dbType}...`);

  if (dbType === 'pg-pool' || dbType === 'pglite') {
    // PostgreSQL Schema
    let schemaSql = postgresSchema;
    try {
      const schemaPath = path.resolve(__dirname, 'schema.sql');
      if (fs.existsSync(schemaPath)) {
        schemaSql = fs.readFileSync(schemaPath, 'utf8');
      }
    } catch (e) {
      // Fallback to embedded schema string
    }

    if (db.exec) {
      await db.exec(schemaSql);
    } else {
      await db.query(schemaSql);
    }
  } else {
    // Ultra-lightweight SQLite Schema (Compatible with Vercel & Render Free Tier)
    const sqliteSchema = `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
        otp_code TEXT,
        otp_expires_at TEXT,
        is_2fa_enabled INTEGER DEFAULT 0,
        account_status TEXT DEFAULT 'ACTIVE',
        admin_auth_code TEXT,
        terms_accepted INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

      CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'Confidential',
        file_path TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
      CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);

      CREATE TABLE IF NOT EXISTS document_permissions (
        id TEXT PRIMARY KEY,
        document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        access_level TEXT NOT NULL CHECK (access_level IN ('read', 'edit')),
        is_revoked INTEGER DEFAULT 0 NOT NULL,
        granted_at TEXT DEFAULT (datetime('now')) NOT NULL,
        revoked_at TEXT,
        granted_by TEXT REFERENCES users(id),
        UNIQUE(document_id, user_id)
      );

      CREATE INDEX IF NOT EXISTS idx_doc_perm_lookup ON document_permissions(document_id, user_id, is_revoked);

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT DEFAULT (datetime('now')) NOT NULL,
        actor_id TEXT REFERENCES users(id),
        actor_email TEXT,
        action TEXT NOT NULL,
        target_resource TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'DENIED')),
        details TEXT DEFAULT '{}',
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id);
      CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);

      CREATE TRIGGER IF NOT EXISTS trg_audit_logs_immutable_upd
      BEFORE UPDATE ON audit_logs
      BEGIN
        SELECT RAISE(ABORT, 'SECURITY VIOLATION: audit_logs is an immutable append-only ledger. UPDATE and DELETE operations are strictly prohibited.');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_audit_logs_immutable_del
      BEFORE DELETE ON audit_logs
      BEGIN
        SELECT RAISE(ABORT, 'SECURITY VIOLATION: audit_logs is an immutable append-only ledger. UPDATE and DELETE operations are strictly prohibited.');
      END;
    `;

    await db.exec(sqliteSchema);
  }

  // Safe schema upgrade helper for existing tables
  const safeAlter = async (sql) => {
    try {
      if (db.exec) await db.exec(sql);
      else await db.query(sql);
    } catch (e) {
      // Column or index already exists, silently proceed
    }
  };

  await safeAlter('ALTER TABLE users ADD COLUMN phone TEXT;');
  await safeAlter("ALTER TABLE users ADD COLUMN account_status TEXT DEFAULT 'ACTIVE';");
  await safeAlter('ALTER TABLE users ADD COLUMN admin_auth_code TEXT;');
  await safeAlter('ALTER TABLE users ADD COLUMN terms_accepted INTEGER DEFAULT 1;');
  await safeAlter('CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);');
  await safeAlter('ALTER TABLE audit_logs ADD COLUMN seq BIGSERIAL;');
  await safeAlter('CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_logs(seq);');

  console.log('[Migration] Database schema migrated successfully.');
}

if (require.main === module) {
  migrate()
    .then(() => {
      console.log('[Migration] Complete.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[Migration Failed]', err);
      process.exit(1);
    });
}

module.exports = { migrate };
