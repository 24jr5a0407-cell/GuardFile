const express = require('express');
const { query } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { verifyChain } = require('../services/auditService');

const router = express.Router();

/**
 * GET /api/audit
 * Administrative and Document Owner view of immutable audit logs.
 * Supports rich filtering: action, status (SUCCESS/DENIED), target, date range.
 */
router.get('/', authenticateToken, async (req, res) => {
  const { action, status, actor, target, fromDate, toDate, limit = 100, offset = 0 } = req.query;

  try {
    let sql = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];
    let paramIdx = 1;

    // Zero-Trust Boundary: Only Admin can view global system logs.
    // Document owners can only view audit logs targeting their owned documents.
    if (req.user.role !== 'admin') {
      if (req.user.role === 'owner') {
        sql += ` AND (actor_id = $${paramIdx} OR target_resource IN (
          SELECT 'document:' || id FROM documents WHERE owner_id = $${paramIdx}
        ) OR target_resource LIKE 'permission:%')`;
        params.push(req.user.id);
        paramIdx++;
      } else {
        return res.status(403).json({ error: 'Forbidden: Insufficient privileges to view audit trail.' });
      }
    }

    if (action) {
      sql += ` AND action = $${paramIdx}`;
      params.push(action);
      paramIdx++;
    }

    if (status) {
      sql += ` AND status = $${paramIdx}`;
      params.push(status.toUpperCase());
      paramIdx++;
    }

    if (actor) {
      sql += ` AND (actor_email ILIKE $${paramIdx} OR actor_id::text ILIKE $${paramIdx})`;
      params.push(`%${actor}%`);
      paramIdx++;
    }

    if (target) {
      sql += ` AND target_resource ILIKE $${paramIdx}`;
      params.push(`%${target}%`);
      paramIdx++;
    }

    if (fromDate) {
      sql += ` AND timestamp >= $${paramIdx}`;
      params.push(fromDate);
      paramIdx++;
    }

    if (toDate) {
      sql += ` AND timestamp <= $${paramIdx}`;
      params.push(toDate);
      paramIdx++;
    }

    sql += ` ORDER BY timestamp DESC, id DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
    params.push(parseInt(limit, 10), parseInt(offset, 10));

    const result = await query(sql, params);

    // Also get total count
    const countSql = sql.replace(/SELECT \* FROM/i, 'SELECT COUNT(*) as total FROM').split('ORDER BY')[0];
    const countRes = await query(countSql, params.slice(0, paramIdx - 1));
    const totalCount = parseInt(countRes.rows[0]?.total || result.rows.length, 10);

    res.json({
      total: totalCount,
      limit: parseInt(limit, 10),
      offset: parseInt(offset, 10),
      logs: result.rows || [],
    });
  } catch (err) {
    console.error('[Audit Query Error]', err);
    res.status(500).json({ error: 'Failed to query audit trail.' });
  }
});

/**
 * GET /api/audit/verify
 * Proves mathematically that the audit ledger has NOT been altered or tampered with.
 */
router.get('/verify', authenticateToken, async (req, res) => {
  try {
    const verification = await verifyChain();
    res.json(verification);
  } catch (err) {
    console.error('[Chain Verification Error]', err);
    res.status(500).json({
      valid: false,
      error: 'Cryptographic ledger verification failed.',
      details: err.message,
    });
  }
});

/**
 * GET /api/audit/stats
 * Provides overview statistics for the administrative dashboard.
 */
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const isOwner = req.user.role === 'owner';
    const ownerFilter = isOwner ? 'WHERE owner_id = $1' : '';
    const ownerParam = isOwner ? [req.user.id] : [];

    const docCountRes = await query(`SELECT COUNT(*) as total FROM documents ${ownerFilter}`, ownerParam);
    const activePermsRes = await query(`SELECT COUNT(*) as total FROM document_permissions WHERE is_revoked = FALSE`);
    const revokedPermsRes = await query(`SELECT COUNT(*) as total FROM document_permissions WHERE is_revoked = TRUE`);
    const deniedEventsRes = await query(`SELECT COUNT(*) as total FROM audit_logs WHERE status = 'DENIED'`);
    const totalAuditRes = await query('SELECT COUNT(*) as total FROM audit_logs');
    const userCountRes = await query('SELECT COUNT(*) as total FROM users');

    res.json({
      totalDocuments: parseInt(docCountRes.rows[0]?.total || 0, 10),
      activePermissions: parseInt(activePermsRes.rows[0]?.total || 0, 10),
      revokedPermissions: parseInt(revokedPermsRes.rows[0]?.total || 0, 10),
      deniedAccessAttempts: parseInt(deniedEventsRes.rows[0]?.total || 0, 10),
      totalAuditTransactions: parseInt(totalAuditRes.rows[0]?.total || 0, 10),
      totalUsers: parseInt(userCountRes.rows[0]?.total || 0, 10),
    });
  } catch (err) {
    console.error('[Audit Stats Error]', err);
    res.status(500).json({ error: 'Failed to compute security statistics.' });
  }
});

module.exports = router;
