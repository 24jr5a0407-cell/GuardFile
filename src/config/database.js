const path = require('path');
const fs = require('fs');
require('dotenv').config();

let dbClient = null;
let dbType = 'none';

/**
 * Initializes the database connection.
 * Priority 1: PostgreSQL server via DATABASE_URL or PG environment variables.
 * Priority 2: Ultra-lightweight embedded SQLite engine (uses ~15MB RAM, perfect for Render 512MB & Vercel).
 */
async function getDb() {
  if (dbClient) {
    return dbClient;
  }

  // 1. Check if external PostgreSQL connection is configured
  const connectionString = process.env.DATABASE_URL;
  const useExternalPostgres = Boolean(connectionString);

  if (useExternalPostgres) {
    try {
      const { Pool } = require('pg');
      const pool = new Pool({
        connectionString,
        ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      });

      const res = await pool.query('SELECT 1 as connected');
      if (res.rows && res.rows.length > 0) {
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
      console.warn(`[Database] External PostgreSQL connection warning (${err.message}). Using lightweight embedded engine.`);
    }
  }

  // 2. Ultra-Lightweight Embedded Engine (SQLite with Postgres parameter compatibility)
  try {
    const sqlite3 = require('sqlite3').verbose();
    // Support serverless /tmp writable dir if running in Vercel/AWS Lambda
    const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
    const dataDir = isServerless ? '/tmp' : path.resolve(__dirname, '../../data');

    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const dbPath = path.join(dataDir, 'trustvault.db');
    const sdb = new sqlite3.Database(dbPath);

    console.log(`[Database] Ultra-lightweight database active at: ${dbPath} (Memory: ~18MB)`);

    dbClient = {
      query(text, params = []) {
        return new Promise((resolve, reject) => {
          // Convert Postgres $1, $2, ... placeholders to SQLite ?
          // Convert ILIKE to LIKE (SQLite LIKE is case-insensitive by default)
          let convertedText = text
            .replace(/\$\d+/g, '?')
            .replace(/\bILIKE\b/gi, 'LIKE')
            .replace(/CURRENT_TIMESTAMP/gi, "datetime('now')")
            .replace(/TRUE/gi, '1')
            .replace(/FALSE/gi, '0');

          const trimmed = convertedText.trim();
          const isSelect = /^SELECT\b/i.test(trimmed);

          if (isSelect) {
            sdb.all(convertedText, params, (err, rows) => {
              if (err) return reject(err);
              // Normalize boolean columns if needed
              const normalized = (rows || []).map(r => {
                if ('is_revoked' in r) r.is_revoked = Boolean(r.is_revoked);
                if ('is_2fa_enabled' in r) r.is_2fa_enabled = Boolean(r.is_2fa_enabled);
                return r;
              });
              resolve({ rows: normalized, rowCount: normalized.length });
            });
          } else {
            sdb.run(convertedText, params, function (err) {
              if (err) return reject(err);
              resolve({
                rows: [],
                rowCount: this.changes,
                lastID: this.lastID,
              });
            });
          }
        });
      },

      exec(sql) {
        return new Promise((resolve, reject) => {
          sdb.exec(sql, (err) => {
            if (err) return reject(err);
            resolve();
          });
        });
      },

      end() {
        return new Promise((resolve) => sdb.close(() => resolve()));
      }
    };

    dbType = 'embedded-sqlite';
    return dbClient;
  } catch (err) {
    console.error('[Database] Failed to initialize embedded database:', err);
    throw err;
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
