const crypto = require('crypto');

/**
 * Calculates SHA-256 hash of a buffer or string.
 */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Calculates SHA-256 hash of a file stream/buffer.
 */
function hashBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Calculates entry hash for the tamper-evident audit ledger chain.
 * Links to previous block hash: SHA-256(id + timestamp + actor_id + action + target + ip + status + prev_hash)
 */
function calculateAuditHash({ id, timestamp, actor_id, action, target_resource, ip_address, status, prev_hash }) {
  const payload = `${id}|${timestamp}|${actor_id || 'anonymous'}|${action}|${target_resource}|${ip_address}|${status}|${prev_hash}`;
  return sha256(payload);
}

/**
 * Generates a cryptographically secure 6-digit numeric OTP code.
 */
function generateOtp() {
  return crypto.randomInt(100000, 999999).toString();
}

/**
 * Generates a secure random token.
 */
function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
  sha256,
  hashBuffer,
  calculateAuditHash,
  generateOtp,
  generateSecureToken,
};
