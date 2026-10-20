const express = require('express');
const { randomUUID: uuidv4 } = require('crypto');
const { query } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { recordEvent } = require('../services/auditService');

const router = express.Router();

/**
 * POST /api/permissions/grant
 * Document owners grant read or edit permissions to named users.
 */
router.post('/grant', authenticateToken, async (req, res) => {
  const { documentId, userId, userEmail, accessLevel = 'read' } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!documentId) {
    return res.status(400).json({ error: 'documentId is required.' });
  }

  if (!['read', 'edit'].includes(accessLevel)) {
    return res.status(400).json({ error: 'accessLevel must be either "read" or "edit".' });
  }

  try {
    // 1. Verify caller is the document owner
    const docRes = await query('SELECT * FROM documents WHERE id = $1', [documentId]);
    if (!docRes.rows || docRes.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const document = docRes.rows[0];
    if (document.owner_id !== req.user.id && req.user.role !== 'admin') {
      await recordEvent({
        actor_id: req.user.id,
        actor_email: req.user.email,
        action: 'GRANT_DENIED',
        target_resource: `permission:${documentId}`,
        ip_address: clientIp,
        status: 'DENIED',
        details: { reason: 'Unauthorized: Only document owner can grant permissions.' },
      });
      return res.status(403).json({ error: 'Forbidden: Only the document owner can grant permissions.' });
    }

    // 2. Identify target recipient user
    let targetUser = null;
    if (userId) {
      const uRes = await query('SELECT id, name, email FROM users WHERE id = $1', [userId]);
      targetUser = uRes.rows && uRes.rows[0];
    } else if (userEmail) {
      const uRes = await query('SELECT id, name, email FROM users WHERE email = $1', [userEmail.toLowerCase().trim()]);
      targetUser = uRes.rows && uRes.rows[0];
    }

    if (!targetUser) {
      return res.status(404).json({ error: 'Recipient user not found in TrustVault directory.' });
    }

    if (targetUser.id === document.owner_id) {
      return res.status(400).json({ error: 'Owner already retains inherent full permissions.' });
    }

    // 3. Upsert permission grant
    const permId = uuidv4();
    await query(
      `INSERT INTO document_permissions (id, document_id, user_id, access_level, is_revoked, granted_at, revoked_at, granted_by)
       VALUES ($1, $2, $3, $4, FALSE, CURRENT_TIMESTAMP, NULL, $5)
       ON CONFLICT (document_id, user_id)
       DO UPDATE SET access_level = $4, is_revoked = FALSE, revoked_at = NULL, granted_at = CURRENT_TIMESTAMP, granted_by = $5`,
      [permId, documentId, targetUser.id, accessLevel, req.user.id]
    );

    // 4. Record immutable audit entry
    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'GRANT',
      target_resource: `permission:${documentId}->${targetUser.id}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: {
        documentTitle: document.title,
        recipientEmail: targetUser.email,
        recipientName: targetUser.name,
        accessLevel,
      },
    });

    res.status(200).json({
      message: `Successfully granted ${accessLevel.toUpperCase()} access to ${targetUser.email}`,
      grant: {
        documentId,
        userId: targetUser.id,
        userEmail: targetUser.email,
        accessLevel,
        isRevoked: false,
      },
    });
  } catch (err) {
    console.error('[Grant Permission Error]', err);
    res.status(500).json({ error: 'Failed to grant permission.' });
  }
});

/**
 * POST /api/permissions/revoke
 * Document owners take back access immediately.
 * Enforces INSTANT REVOCATION: is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP.
 */
router.post('/revoke', authenticateToken, async (req, res) => {
  const { documentId, userId, reason = 'Access revoked by owner' } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!documentId || !userId) {
    return res.status(400).json({ error: 'documentId and userId are required.' });
  }

  try {
    // 1. Verify caller is owner
    const docRes = await query('SELECT * FROM documents WHERE id = $1', [documentId]);
    if (!docRes.rows || docRes.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const document = docRes.rows[0];
    if (document.owner_id !== req.user.id && req.user.role !== 'admin') {
      await recordEvent({
        actor_id: req.user.id,
        actor_email: req.user.email,
        action: 'REVOKE_DENIED',
        target_resource: `permission:${documentId}->${userId}`,
        ip_address: clientIp,
        status: 'DENIED',
        details: { reason: 'Caller is not the document owner.' },
      });
      return res.status(403).json({ error: 'Forbidden: Only the document owner can revoke permissions.' });
    }

    // 2. Fetch target user
    const targetUserRes = await query('SELECT id, name, email FROM users WHERE id = $1', [userId]);
    const targetUser = targetUserRes.rows && targetUserRes.rows[0];

    // 3. Perform instant revocation in real-time
    const updateRes = await query(
      `UPDATE document_permissions
       SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
       WHERE document_id = $1 AND user_id = $2 AND is_revoked = FALSE
       RETURNING id`,
      [documentId, userId]
    );

    const affected = (updateRes.rows && updateRes.rows.length > 0) || updateRes.rowCount > 0;
    if (!affected) {
      return res.status(404).json({ error: 'Active permission grant not found or already revoked.' });
    }

    // 4. Record immutable REVOKE event in audit trail
    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'REVOKE',
      target_resource: `permission:${documentId}->${userId}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: {
        documentTitle: document.title,
        revokedUserEmail: targetUser ? targetUser.email : userId,
        reason,
        timestamp: new Date().toISOString(),
      },
    });

    res.json({
      message: `Access immediately revoked for user ${targetUser ? targetUser.email : userId}. All future attempts will be rejected.`,
      revocation: {
        documentId,
        userId,
        revokedAt: new Date().toISOString(),
        isRevoked: true,
      },
    });
  } catch (err) {
    console.error('[Revoke Permission Error]', err);
    res.status(500).json({ error: 'Failed to revoke permission.' });
  }
});

/**
 * GET /api/permissions/document/:id
 * Retrieve all active and revoked grants for a document.
 */
router.get('/document/:id', authenticateToken, async (req, res) => {
  const documentId = req.params.id;

  try {
    const docRes = await query('SELECT * FROM documents WHERE id = $1', [documentId]);
    if (!docRes.rows || docRes.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const document = docRes.rows[0];
    if (document.owner_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Only document owner or admin can view permissions roster.' });
    }

    const permsRes = await query(
      `SELECT dp.id, dp.access_level, dp.is_revoked, dp.granted_at, dp.revoked_at,
              u.id as user_id, u.name as user_name, u.email as user_email
       FROM document_permissions dp
       JOIN users u ON dp.user_id = u.id
       WHERE dp.document_id = $1
       ORDER BY dp.granted_at DESC`,
      [documentId]
    );

    res.json({ permissions: permsRes.rows || [] });
  } catch (err) {
    console.error('[Get Permissions Error]', err);
    res.status(500).json({ error: 'Failed to retrieve permissions list.' });
  }
});

module.exports = router;
