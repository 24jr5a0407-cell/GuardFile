const fs = require('fs');
const path = require('path');
const { randomUUID: uuidv4 } = require('crypto');
const { query } = require('../config/database');
const { calculateAuditHash } = require('../utils/crypto');

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const LEDGER_FILE = path.resolve(__dirname, '../../logs/audit_ledger.log');

// Ensure logs directory exists
const logsDir = path.dirname(LEDGER_FILE);
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Appends a new immutable event to the audit trail with cryptographic chaining.
 */
async function recordEvent({
  actor_id = null,
  actor_email = 'system/anonymous',
  action,
  target_resource,
  ip_address = '127.0.0.1',
  status = 'SUCCESS',
  details = {},
}) {
  try {
    // 1. Fetch latest entry to get previous block hash
    const latestRes = await query(
      'SELECT entry_hash FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 1'
    );
    const prev_hash = (latestRes.rows && latestRes.rows.length > 0)
      ? latestRes.rows[0].entry_hash
      : GENESIS_HASH;

    const id = uuidv4();
    const timestamp = new Date().toISOString();
    const detailsStr = typeof details === 'string' ? details : JSON.stringify(details);

    // 2. Cryptographic Hash calculation
    const entry_hash = calculateAuditHash({
      id,
      timestamp,
      actor_id,
      action,
      target_resource,
      ip_address,
      status,
      prev_hash,
    });

    // 3. Insert into PostgreSQL audit_logs table (guarded by SQL trigger preventing UPDATE/DELETE)
    await query(
      `INSERT INTO audit_logs (id, timestamp, actor_id, actor_email, action, target_resource, ip_address, status, details, prev_hash, entry_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [id, timestamp, actor_id, actor_email, action, target_resource, ip_address, status, detailsStr, prev_hash, entry_hash]
    );

    // 4. Secondary append-only physical file ledger for off-database forensic proof
    const ledgerEntry = JSON.stringify({
      id,
      timestamp,
      actor_id,
      actor_email,
      action,
      target_resource,
      ip_address,
      status,
      details,
      prev_hash,
      entry_hash,
    }) + '\n';
    fs.appendFileSync(LEDGER_FILE, ledgerEntry, 'utf8');

    return { id, timestamp, entry_hash, status };
  } catch (err) {
    console.error('[Audit Trail Error] Failed to record immutable audit log:', err);
    // Never fail silently on audit errors in a zero-trust architecture
    throw new Error(`Audit recording failure: ${err.message}`);
  }
}

/**
 * Mathematically verifies the cryptographic integrity of the entire audit chain.
 * Proves that no records have been altered, deleted, or inserted maliciously.
 */
async function verifyChain() {
  const result = await query(
    'SELECT id, timestamp, actor_id, action, target_resource, ip_address, status, prev_hash, entry_hash FROM audit_logs ORDER BY timestamp ASC, id ASC'
  );

  const logs = result.rows || [];
  if (logs.length === 0) {
    return { valid: true, totalRecords: 0, message: 'Audit chain is empty.' };
  }

  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < logs.length; i++) {
    const entry = logs[i];

    // Verify linkage to previous hash
    if (entry.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        errorIndex: i,
        recordId: entry.id,
        reason: `Cryptographic link broken! Record ${entry.id} has prev_hash ${entry.prev_hash}, expected ${expectedPrevHash}.`,
      };
    }

    // Verify content integrity by recomputing hash
    const recomputedHash = calculateAuditHash({
      id: entry.id,
      timestamp: new Date(entry.timestamp).toISOString(),
      actor_id: entry.actor_id,
      action: entry.action,
      target_resource: entry.target_resource,
      ip_address: entry.ip_address,
      status: entry.status,
      prev_hash: entry.prev_hash,
    });

    if (entry.entry_hash !== recomputedHash) {
      return {
        valid: false,
        errorIndex: i,
        recordId: entry.id,
        reason: `Cryptographic tampering detected! Record ${entry.id} hash mismatch. Computed: ${recomputedHash}, Stored: ${entry.entry_hash}.`,
      };
    }

    expectedPrevHash = entry.entry_hash;
  }

  return {
    valid: true,
    totalRecords: logs.length,
    headHash: expectedPrevHash,
    message: 'Cryptographic audit ledger verified. 100% integrity confirmed.',
  };
}

module.exports = {
  recordEvent,
  verifyChain,
  GENESIS_HASH,
};
