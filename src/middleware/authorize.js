const { query } = require('../config/database');
const { recordEvent } = require('../services/auditService');

/**
 * Strict Zero-Trust Object-Level Authorization Middleware
 *
 * Verifies that the authenticated user has real-time, unrevoked permission
 * to perform the requested action (read or edit) on the target document.
 * Refusals are recorded in the immutable audit trail with IP address and timestamp.
 */
function authorizeDocument(requiredAccess = 'read') {
  return async (req, res, next) => {
    const documentId = req.params.id || req.body.documentId || req.query.documentId;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    if (!documentId) {
      return res.status(400).json({ error: 'Missing document identifier in request parameters.' });
    }

    try {
      // 1. Fetch document metadata from database
      const docRes = await query('SELECT * FROM documents WHERE id = $1', [documentId]);
      if (!docRes.rows || docRes.rows.length === 0) {
        // Record denied attempt for non-existent document (scanning defense)
        await recordEvent({
          actor_id: req.user ? req.user.id : null,
          actor_email: req.user ? req.user.email : 'unauthenticated',
          action: 'READ_DENIED',
          target_resource: `document:${documentId}`,
          ip_address: clientIp,
          status: 'DENIED',
          details: { reason: 'Document does not exist or invalid ID.' },
        });

        return res.status(404).json({ error: 'Document not found.' });
      }

      const document = docRes.rows[0];

      // 2. Check if the user is the document owner
      const isOwner = req.user && req.user.id === document.owner_id;
      if (isOwner) {
        req.document = document;
        req.accessLevel = 'owner';
        return next();
      }

      // 3. Query real-time permissions table for active, unrevoked grant
      const permRes = await query(
        `SELECT id, access_level, is_revoked, granted_at, revoked_at
         FROM document_permissions
         WHERE document_id = $1 AND user_id = $2`,
        [documentId, req.user.id]
      );

      const perm = permRes.rows && permRes.rows.length > 0 ? permRes.rows[0] : null;

      // 4. Strict Zero-Trust Authorization Evaluation
      let denialReason = null;

      if (!perm) {
        denialReason = 'No permission grant exists for this user.';
      } else if (perm.is_revoked) {
        denialReason = `Permission was revoked on ${perm.revoked_at}. Instant access termination enforced.`;
      } else if (requiredAccess === 'edit' && perm.access_level !== 'edit') {
        denialReason = `Insufficient grant level: user possesses "${perm.access_level}" access, but "edit" is required.`;
      }

      // If unauthorized, log refusal in immutable audit trail and block immediately
      if (denialReason) {
        await recordEvent({
          actor_id: req.user.id,
          actor_email: req.user.email,
          action: 'READ_DENIED',
          target_resource: `document:${documentId}`,
          ip_address: clientIp,
          status: 'DENIED',
          details: {
            reason: denialReason,
            documentTitle: document.title,
            requiredAccess,
            userRole: req.user.role,
          },
        });

        return res.status(403).json({
          error: 'Access Denied: Forbidden',
          message: 'Zero-Trust Policy: You do not possess an active, unrevoked permission grant for this document.',
          reason: denialReason,
        });
      }

      // 5. User is actively authorized
      req.document = document;
      req.accessLevel = perm.access_level;
      next();
    } catch (err) {
      console.error('[Authorization Middleware Error]', err);
      return res.status(500).json({ error: 'Internal security evaluation error.' });
    }
  };
}

module.exports = {
  authorizeDocument,
};
