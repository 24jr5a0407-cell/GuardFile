/**
 * Strict Magic Byte & File Signature Validator
 * Defends against MIME-type spoofing, extension renaming, and disguised executables.
 */

// Disallowed dangerous file headers
const DANGEROUS_SIGNATURES = [
  { name: 'Windows Executable (MZ/PE)', magic: [0x4d, 0x5a] },
  { name: 'Linux Executable (ELF)', magic: [0x7f, 0x45, 0x4c, 0x46] },
  { name: 'Mach-O Binary (macOS)', magic: [0xfe, 0xed, 0xfa, 0xce] },
  { name: 'Mach-O Binary 64-bit', magic: [0xfe, 0xed, 0xfa, 0xcf] },
  { name: 'Java Class Bytecode', magic: [0xca, 0xfe, 0xba, 0xbe] },
];

/**
 * Checks if the buffer starts with specific magic bytes.
 */
function matchesMagic(buffer, magicBytes) {
  if (buffer.length < magicBytes.length) return false;
  for (let i = 0; i < magicBytes.length; i++) {
    if (buffer[i] !== magicBytes[i]) return false;
  }
  return true;
}

/**
 * Checks if a buffer represents clean ASCII / UTF-8 text (for txt, csv, json).
 */
function isCleanText(buffer) {
  const checkLength = Math.min(buffer.length, 1024);
  for (let i = 0; i < checkLength; i++) {
    const byte = buffer[i];
    // Disallow null bytes and non-printable control characters (except tab, CR, LF)
    if (byte === 0 || (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13)) {
      return false;
    }
  }
  return true;
}

/**
 * Validates the file buffer against its claimed extension and MIME type.
 * Returns { valid: boolean, detectedType: string, reason?: string }
 */
function validateFileSignature(buffer, originalname, declaredMimeType) {
  if (!buffer || buffer.length === 0) {
    return { valid: false, reason: 'File is empty (0 bytes).' };
  }

  // 1. First, verify no dangerous executable signatures exist
  for (const dangerous of DANGEROUS_SIGNATURES) {
    if (matchesMagic(buffer, dangerous.magic)) {
      return {
        valid: false,
        reason: `Rejected: File header matches dangerous executable signature (${dangerous.name}).`,
      };
    }
  }

  // Check for script tags or shebang in text
  const initialText = buffer.slice(0, 100).toString('utf8');
  if (initialText.startsWith('#!') || /<\?php/i.test(initialText) || /<script/i.test(initialText)) {
    return {
      valid: false,
      reason: 'Rejected: File contains executable script header or embedded executable code.',
    };
  }

  const ext = (originalname.split('.').pop() || '').toLowerCase();

  // 2. Validate format-specific magic bytes
  switch (ext) {
    case 'pdf': {
      // PDF starts with %PDF- (0x25, 0x50, 0x44, 0x46, 0x2D)
      const pdfMagic = [0x25, 0x50, 0x44, 0x46, 0x2d];
      if (!matchesMagic(buffer, pdfMagic)) {
        return { valid: false, reason: 'Invalid PDF: File does not start with valid %PDF- magic bytes.' };
      }
      return { valid: true, detectedType: 'application/pdf' };
    }

    case 'png': {
      // PNG magic: 89 50 4E 47 0D 0A 1A 0A
      const pngMagic = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
      if (!matchesMagic(buffer, pngMagic)) {
        return { valid: false, reason: 'Invalid PNG: File does not start with valid PNG magic bytes.' };
      }
      return { valid: true, detectedType: 'image/png' };
    }

    case 'jpg':
    case 'jpeg': {
      // JPEG starts with FF D8 FF
      const jpegMagic = [0xff, 0xd8, 0xff];
      if (!matchesMagic(buffer, jpegMagic)) {
        return { valid: false, reason: 'Invalid JPEG: File does not start with valid JPEG magic bytes.' };
      }
      return { valid: true, detectedType: 'image/jpeg' };
    }

    case 'docx':
    case 'xlsx': {
      // Office OpenXML files are ZIP archives starting with PK\x03\x04
      const zipMagic = [0x50, 0x4b, 0x03, 0x04];
      if (!matchesMagic(buffer, zipMagic)) {
        return { valid: false, reason: 'Invalid Office document: File does not start with valid OpenXML ZIP header.' };
      }
      return {
        valid: true,
        detectedType: ext === 'docx' ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      };
    }

    case 'txt':
    case 'csv':
    case 'json': {
      if (!isCleanText(buffer)) {
        return { valid: false, reason: 'Invalid text file: File contains binary or unprintable control characters.' };
      }
      return { valid: true, detectedType: ext === 'csv' ? 'text/csv' : ext === 'json' ? 'application/json' : 'text/plain' };
    }

    default:
      return { valid: false, reason: `File extension .${ext} is not in the allowed list (pdf, png, jpg, jpeg, docx, xlsx, txt, csv, json).` };
  }
}

module.exports = {
  validateFileSignature,
  matchesMagic,
  isCleanText,
};
