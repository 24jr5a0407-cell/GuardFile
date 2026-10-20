const fs = require('fs');
const path = require('path');
const { getDb, getDbType } = require('../config/database');

async function migrate() {
  const db = await getDb();
  const dbType = getDbType();
  console.log(`[Migration] Starting database migration for engine: ${dbType}...`);

  if (dbType === 'pg-pool' || dbType === 'pglite') {
    // PostgreSQL Schema
    const schemaPath = path.resolve(__dirname, 'schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');

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
