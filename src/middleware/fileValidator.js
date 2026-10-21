const multer = require('multer');
const path = require('path');
const { validateFileSignature } = require('../utils/magicBytes');

const MAX_SIZE_MB = parseInt(process.env.MAX_FILE_SIZE_MB || '15', 10);
const MAX_BYTES = MAX_SIZE_MB * 1024 * 1024;

const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_BYTES,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    // Basic extension check
    const ext = (path.extname(file.originalname) || '').toLowerCase().replace('.', '');
    const allowed = ['pdf', 'png', 'jpg', 'jpeg', 'docx', 'xlsx', 'txt', 'csv', 'json'];

    if (!allowed.includes(ext)) {
      return cb(new Error(`Forbidden file extension .${ext}. Allowed types: ${allowed.join(', ')}`), false);
    }

    // Path traversal check on original filename
    if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
      return cb(new Error('Invalid filename: Path traversal sequence detected.'), false);
    }

    cb(null, true);
  },
});

const uploadMultiple = multer({
  storage,
  limits: {
    fileSize: MAX_BYTES,
    files: 10,
  },
  fileFilter: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '').toLowerCase().replace('.', '');
    const allowed = ['pdf', 'png', 'jpg', 'jpeg', 'docx', 'xlsx', 'txt', 'csv', 'json'];

    if (!allowed.includes(ext)) {
      return cb(new Error(`Forbidden file extension .${ext}. Allowed types: ${allowed.join(', ')}`), false);
    }

    if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
      return cb(new Error('Invalid filename: Path traversal sequence detected.'), false);
    }

    cb(null, true);
  },
});

/**
 * Middleware that runs after multer memory buffer is populated.
 * Strictly verifies magic bytes and file signature.
 */
function validateUploadedFile(req, res, next) {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded. Please select a valid document.' });
  }

  const { buffer, originalname, mimetype } = req.file;

  const result = validateFileSignature(buffer, originalname, mimetype);
  if (!result.valid) {
    return res.status(400).json({
      error: 'Security File Validation Failed',
      reason: result.reason,
    });
  }

  // Attach detected MIME type if refined
  if (result.detectedType) {
    req.file.mimetype = result.detectedType;
  }

  next();
}

module.exports = {
  upload,
  uploadMultiple,
  validateUploadedFile,
  MAX_BYTES,
};
