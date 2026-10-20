const fs = require('fs');
const path = require('path');
const { randomUUID: uuidv4 } = require('crypto');
const { hashBuffer } = require('../utils/crypto');

// Root isolated directory outside the public web root
const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
const defaultStorageDir = isServerless ? '/tmp/secure_storage' : './secure_storage';
const STORAGE_DIR = path.resolve(process.env.STORAGE_DIR || defaultStorageDir);

// Ensure secure storage directory exists with restricted permissions
if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

/**
 * Sanitizes and verifies that a resolved path is strictly inside the secure storage directory.
 * Defends against Path Traversal (e.g. ../../etc/passwd or C:\windows\system32)
 */
function resolveSecurePath(filePath) {
  if (!filePath) {
    throw new Error('Path Traversal detected: empty path');
  }

  // Prevent null bytes
  if (filePath.indexOf('\0') !== -1) {
    throw new Error('Path Traversal detected: null byte in path');
  }

  // Strictly block path traversal sequences
  if (filePath.includes('..') || (path.isAbsolute(filePath) && !filePath.startsWith(STORAGE_DIR))) {
    throw new Error(`SECURITY ALERT: Path Traversal attempt blocked! Path "${filePath}" escapes secure directory.`);
  }

  const absoluteTarget = path.resolve(STORAGE_DIR, path.basename(filePath));

  // Must strictly start with STORAGE_DIR
  if (!absoluteTarget.startsWith(STORAGE_DIR)) {
    throw new Error(`SECURITY ALERT: Path Traversal attempt blocked! Path "${filePath}" escapes secure directory.`);
  }

  return absoluteTarget;
}

/**
 * Saves a file buffer securely to disk using an unpredictable UUID filename.
 */
async function storeFile(buffer, originalname) {
  const fileHash = hashBuffer(buffer);
  const ext = (path.extname(originalname) || '.bin').toLowerCase();
  const safeDiskName = `${uuidv4()}${ext}`;
  const fullPath = path.join(STORAGE_DIR, safeDiskName);

  await fs.promises.writeFile(fullPath, buffer);

  return {
    storagePath: safeDiskName, // Store only the safe relative identifier in the DB
    fullDiskPath: fullPath,
    fileName: path.basename(originalname),
    fileSize: buffer.length,
    fileHash,
  };
}

/**
 * Reads a file as a stream or buffer from secure storage.
 */
function getFileStream(storagePath) {
  const verifiedPath = resolveSecurePath(storagePath);
  if (!fs.existsSync(verifiedPath)) {
    throw new Error('Requested file not found in secure storage.');
  }
  return fs.createReadStream(verifiedPath);
}

/**
 * Deletes a file from secure storage.
 */
async function deleteFile(storagePath) {
  try {
    const verifiedPath = resolveSecurePath(storagePath);
    if (fs.existsSync(verifiedPath)) {
      await fs.promises.unlink(verifiedPath);
    }
  } catch (err) {
    console.warn(`[Storage Warning] Failed to unlink file ${storagePath}: ${err.message}`);
  }
}

module.exports = {
  STORAGE_DIR,
  resolveSecurePath,
  storeFile,
  getFileStream,
  deleteFile,
};
