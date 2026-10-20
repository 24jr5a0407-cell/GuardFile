const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

let dbClient = null;
let dbType = 'none';

/**
 * Initializes the database connection.
 * Priority 1: Remote/Local PostgreSQL server via DATABASE_URL or PG environment variables.
 * Priority 2: Embedded PostgreSQL engine (PGlite) storing state in ./data/postgres.
 */
async function getDb() {
  if (dbClient) {
    return dbClient;
  }

  // Check if live PostgreSQL connection is configured
  const connectionString = process.env.DATABASE_URL;
  const useExternalPostgres = Boolean(connectionString || process.env.FORCE_EXTERNAL_PG === 'true');

  if (useExternalPostgres) {
    try {
      const pool = new Pool({
        connectionString: connectionString || undefined,
        host: process.env.PGHOST || 'localhost',
        port: parseInt(process.env.PGPORT || '5432', 10),
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD || 'postgres',
        database: process.env.PGDATABASE || 'trustvault',
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 3000,
      });

      // Quick test query to ensure server is reachable
      const res = await pool.query('SELECT 1 as connected');
      if (res.rows && res.rows[0].connected === 1) {
        console.log('[Database] Connected to external PostgreSQL server.');
        dbClient = {
          query: (text, params) => pool.query(text, params),
          exec: (sql) => pool.query(sql),
          end: () => pool.end(),
        };
        dbType = 'pg-pool';
        return dbClient;
      }
    } catch (err) {
      console.warn(`[Database] External PostgreSQL unreachable (${err.message}). Falling back to embedded PostgreSQL.`);
    }
  }

  // Fallback to embedded PostgreSQL (PGlite)
  try {
    const { PGlite } = require('@electric-sql/pglite');
    const dataDir = path.resolve(__dirname, '../../data/postgres');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const pglite = new PGlite(dataDir);
    await pglite.waitReady;
    console.log(`[Database] Embedded PostgreSQL (PGlite) initialized at: ${dataDir}`);

    dbClient = {
      async query(text, params = []) {
        const result = await pglite.query(text, params);
        const count = typeof result.affectedRows === 'number'
          ? result.affectedRows
          : (result.rows ? result.rows.length : 0);
        return {
          rows: result.rows || [],
          rowCount: count,
        };
      },
      async exec(sql) {
        return pglite.exec(sql);
      },
      async end() {
        if (pglite.close) await pglite.close();
      }
    };

    dbType = 'pglite';
    return dbClient;
  } catch (embeddedErr) {
    console.error('[Database] Failed to initialize embedded PostgreSQL:', embeddedErr);
    throw embeddedErr;
  }
}

async function query(text, params = []) {
  const db = await getDb();
  return db.query(text, params);
}

async function exec(sql) {
  const db = await getDb();
  return db.exec(sql);
}

module.exports = {
  getDb,
  query,
  exec,
  getDbType: () => dbType,
};
