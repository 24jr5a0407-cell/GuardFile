const express = require('express');
const { randomUUID: uuidv4 } = require('crypto');
const path = require('path');
const { query } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { authorizeDocument } = require('../middleware/authorize');
const { upload, validateUploadedFile } = require('../middleware/fileValidator');
const { storeFile, getFileStream, deleteFile } = require('../services/storageService');
const { recordEvent } = require('../services/auditService');

const router = express.Router();

/**
 * POST /api/documents/upload
 * Secure document upload with MIME & magic byte verification.
 * Only Owners and Admins can upload.
 */
router.post(
  '/upload',
  authenticateToken,
  requireRole(['owner', 'admin']),
  upload.single('file'),
  validateUploadedFile,
  async (req, res) => {
    const { title, category = 'Confidential' } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    if (!title || title.trim().length === 0) {
      return res.status(400).json({ error: 'Document title is required.' });
    }

    try {
      // Store securely on isolated disk
      const stored = await storeFile(req.file.buffer, req.file.originalname);
      const docId = uuidv4();

      await query(
        `INSERT INTO documents (id, title, category, file_path, file_name, file_size, mime_type, file_hash, owner_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          docId,
          title.trim(),
          category.trim(),
          stored.storagePath,
          stored.fileName,
          stored.fileSize,
          req.file.mimetype,
          stored.fileHash,
          req.user.id,
        ]
      );

      // Record immutable audit event
      await recordEvent({
        actor_id: req.user.id,
        actor_email: req.user.email,
        action: 'UPLOAD',
        target_resource: `document:${docId}`,
        ip_address: clientIp,
        status: 'SUCCESS',
        details: {
          title: title.trim(),
          category: category.trim(),
          fileName: stored.fileName,
          fileSize: stored.fileSize,
          fileHash: stored.fileHash,
        },
      });

      res.status(201).json({
        message: 'Document uploaded and registered securely.',
        document: {
          id: docId,
          title: title.trim(),
          category: category.trim(),
          fileName: stored.fileName,
          fileSize: stored.fileSize,
          mimeType: req.file.mimetype,
          fileHash: stored.fileHash,
          ownerId: req.user.id,
        },
      });
    } catch (err) {
      console.error('[Upload Error]', err);
      res.status(500).json({ error: 'Failed to securely store document.' });
    }
  }
);

/**
 * GET /api/documents
 * Lists documents accessible to the caller, with multi-parameter search & filtering.
 * Enforces Zero-Trust isolation: Users only see documents they own or have active grants for.
 */
router.get('/', authenticateToken, async (req, res) => {
  const { q, category, owner, fromDate, toDate } = req.query;

  try {
    let sql = '';
    const params = [];
    let paramIdx = 1;

    if (req.user.role === 'admin') {
      // Admins see document metadata registry for system administration
      sql = `
        SELECT d.id, d.title, d.category, d.file_name, d.file_size, d.mime_type, d.file_hash, d.created_at,
               u.name as owner_name, u.email as owner_email,
               'admin' as user_access_level
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE 1=1
      `;
    } else {
      // Non-admins: ONLY owned documents OR documents with active, unrevoked grants
      sql = `
        SELECT d.id, d.title, d.category, d.file_name, d.file_size, d.mime_type, d.file_hash, d.created_at,
               u.name as owner_name, u.email as owner_email,
               CASE
                 WHEN d.owner_id = $${paramIdx} THEN 'owner'
                 ELSE dp.access_level
               END as user_access_level
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        LEFT JOIN document_permissions dp ON dp.document_id = d.id AND dp.user_id = $${paramIdx} AND dp.is_revoked = FALSE
        WHERE (d.owner_id = $${paramIdx} OR (dp.user_id = $${paramIdx} AND dp.is_revoked = FALSE))
      `;
      params.push(req.user.id);
      paramIdx++;
    }

    // Search by title or file name
    if (q) {
      sql += ` AND (d.title ILIKE $${paramIdx} OR d.file_name ILIKE $${paramIdx})`;
      params.push(`%${q}%`);
      paramIdx++;
    }

    // Filter by category
    if (category) {
      sql += ` AND d.category ILIKE $${paramIdx}`;
      params.push(`%${category}%`);
      paramIdx++;
    }

    // Filter by owner
    if (owner) {
      sql += ` AND (u.name ILIKE $${paramIdx} OR u.email ILIKE $${paramIdx})`;
      params.push(`%${owner}%`);
      paramIdx++;
    }

    // Date filters
    if (fromDate) {
      sql += ` AND d.created_at >= $${paramIdx}`;
      params.push(fromDate);
      paramIdx++;
    }

    if (toDate) {
      sql += ` AND d.created_at <= $${paramIdx}`;
      params.push(toDate);
      paramIdx++;
    }

    sql += ' ORDER BY d.created_at DESC';

    const result = await query(sql, params);
    res.json({ documents: result.rows || [] });
  } catch (err) {
    console.error('[Document List Error]', err);
    res.status(500).json({ error: 'Failed to retrieve documents.' });
  }
});

/**
 * GET /api/documents/:id
 * Retrieve specific document details.
 * Guarded by authorizeDocument('read').
 */
router.get('/:id', authenticateToken, authorizeDocument('read'), async (req, res) => {
  res.json({
    document: {
      ...req.document,
      userAccessLevel: req.accessLevel,
    },
  });
});

/**
 * GET /api/documents/:id/download
 * Secure streaming file download.
 * Enforces real-time permissions check and records READ_SUCCESS in the audit trail.
 */
router.get('/:id/download', authenticateToken, authorizeDocument('read'), async (req, res) => {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  try {
    // Record verified read in audit trail
    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'READ_SUCCESS',
      target_resource: `document:${req.document.id}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: {
        operation: 'download',
        fileName: req.document.file_name,
        fileHash: req.document.file_hash,
        accessLevel: req.accessLevel,
      },
    });

    const fileStream = getFileStream(req.document.file_path);

    res.setHeader('Content-Type', req.document.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(req.document.file_name)}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    fileStream.pipe(res);
  } catch (err) {
    console.error('[Download Stream Error]', err);
    res.status(500).json({ error: 'Unable to stream confidential file.' });
  }
});

/**
 * GET /api/documents/:id/preview
 * In-browser secure preview (inline display).
 * Enforces real-time permissions check and records READ_SUCCESS in the audit trail.
 */
router.get('/:id/preview', authenticateToken, authorizeDocument('read'), async (req, res) => {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  try {
    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'READ_SUCCESS',
      target_resource: `document:${req.document.id}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: {
        operation: 'preview',
        fileName: req.document.file_name,
        accessLevel: req.accessLevel,
      },
    });

    const fileStream = getFileStream(req.document.file_path);

    res.setHeader('Content-Type', req.document.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(req.document.file_name)}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store, private');

    fileStream.pipe(res);
  } catch (err) {
    console.error('[Preview Stream Error]', err);
    res.status(500).json({ error: 'Unable to preview confidential file.' });
  }
});

/**
 * PUT /api/documents/:id
 * Update document metadata (title, category).
 * Guarded by authorizeDocument('edit').
 */
router.put('/:id', authenticateToken, authorizeDocument('edit'), async (req, res) => {
  const { title, category } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!title && !category) {
    return res.status(400).json({ error: 'At least title or category must be supplied.' });
  }

  try {
    const updatedTitle = title ? title.trim() : req.document.title;
    const updatedCategory = category ? category.trim() : req.document.category;

    await query(
      `UPDATE documents SET title = $1, category = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3`,
      [updatedTitle, updatedCategory, req.document.id]
    );

    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'EDIT',
      target_resource: `document:${req.document.id}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: {
        previousTitle: req.document.title,
        updatedTitle,
        previousCategory: req.document.category,
        updatedCategory,
      },
    });

    res.json({
      message: 'Document metadata updated successfully.',
      document: {
        id: req.document.id,
        title: updatedTitle,
        category: updatedCategory,
      },
    });
  } catch (err) {
    console.error('[Edit Document Error]', err);
    res.status(500).json({ error: 'Failed to update document.' });
  }
});

/**
 * DELETE /api/documents/:id
 * Permanently removes document and its stored physical file.
 * Only the document owner can delete their document.
 */
router.delete('/:id', authenticateToken, async (req, res) => {
  const documentId = req.params.id;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  try {
    const docRes = await query('SELECT * FROM documents WHERE id = $1', [documentId]);
    if (!docRes.rows || docRes.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    const document = docRes.rows[0];

    // Only owner (or admin) can delete
    if (document.owner_id !== req.user.id && req.user.role !== 'admin') {
      await recordEvent({
        actor_id: req.user.id,
        actor_email: req.user.email,
        action: 'DELETE_DENIED',
        target_resource: `document:${documentId}`,
        ip_address: clientIp,
        status: 'DENIED',
        details: { reason: 'Caller is not the document owner.' },
      });
      return res.status(403).json({ error: 'Forbidden: Only the document owner can delete this document.' });
    }

    // Unlink physical file from secure storage
    await deleteFile(document.file_path);

    // Delete DB record
    await query('DELETE FROM documents WHERE id = $1', [documentId]);

    // Record immutable audit deletion
    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'DELETE',
      target_resource: `document:${documentId}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: {
        deletedTitle: document.title,
        deletedFileName: document.file_name,
        deletedHash: document.file_hash,
      },
    });

    res.json({ message: 'Document and physical asset permanently destroyed.' });
  } catch (err) {
    console.error('[Delete Document Error]', err);
    res.status(500).json({ error: 'Failed to delete document.' });
  }
});

module.exports = router;
