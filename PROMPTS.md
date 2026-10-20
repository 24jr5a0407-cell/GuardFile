# TrustVault — AI Engineering Interaction Log (PROMPTS.md)
**Project:** TrustVault — Secure Zero-Trust Document Sharing Platform  
**Challenge:** Snovasys Fresher Hiring Challenge 2026  
**Candidate:** Solo Engineering Submission  

This log documents five critical engineering decisions where an AI coding tool produced flawed, insecure, or substandard code, how the vulnerability was identified, and the secure implementation chosen instead.

---

### Entry 1: Authorization Middleware & Session State (Access Control)
- **Date:** 2026-10-19  
- **Prompt:**  
  > *"Write an Express authorization middleware that checks if a user has access to a document. Make it high-performance so we don't query the database on every download request."*
- **What it produced:**  
  The AI suggested encoding the user's active document grants into the JWT session token at login (e.g. `jwt.sign({ id, permissions: ['doc-1:read', 'doc-2:read'] })`), or caching the user's permission set in memory with a 15-minute TTL.
- **What was wrong with it specifically:**  
  This violates **Non-Negotiable Rule Three: Taking access away works immediately**. If an owner revokes access to a confidential contract, the user's pre-issued JWT token or cached permission map remains valid until expiration. During that 15-minute to 24-hour window, the revoked user can continue downloading the file undetected. In security engineering, caching authorization decisions on sensitive assets is a critical vulnerability.
- **What we did instead:**  
  Implemented **Real-Time Object-Level Authorization** (`src/middleware/authorize.js`). We deliberately rejected token-based permission caching. Every single download, preview, and edit request executes a sub-millisecond indexed SQL query against `document_permissions` (`document_id = $1 AND user_id = $2 AND is_revoked = FALSE`). When an owner clicks Revoke, `is_revoked = TRUE` is committed immediately, causing the very next request within milliseconds to fail with HTTP 403.
- **Reference Code / Commit:** [`src/middleware/authorize.js`](file:///c:/Users/MD%20ARSHAD/Desktop/GuardFile/src/middleware/authorize.js)

---

### Entry 2: Audit Trail Immutability & Tampering Defense (Audit Trail)
- **Date:** 2026-10-19  
- **Prompt:**  
  > *"Design the audit logging system for TrustVault so we can track uploads, downloads, and permission changes."*
- **What it produced:**  
  A basic database model with columns `id`, `timestamp`, `action`, `user_id`, and `is_deleted` (soft deletes). It also suggested an endpoint `DELETE /api/audit/:id` accessible to Administrators for "log retention cleanup".
- **What was wrong with it specifically:**  
  This fatally fails **Non-Negotiable Rule Two: You can prove who reached it... An audit trail that can be quietly altered is not evidence**. An administrator endpoint that deletes logs or a table without SQL-level immutability allows any rogue insider or compromised account to quietly purge exfiltration records. Furthermore, soft-deletes (`is_deleted = true`) can be flipped or deleted directly.
- **What we did instead:**  
  1. Built a **PostgreSQL Database Trigger** (`prevent_audit_log_tampering`) that immediately throws a SQL exception on any `UPDATE` or `DELETE` attempt against `audit_logs`.
  2. Implemented **Cryptographic SHA-256 Hash Chaining**: each log entry computes `entry_hash = SHA-256(fields + prev_hash)`. Any altered or deleted record permanently breaks the cryptographic chain.
  3. Added an audit chain verification algorithm (`verifyChain()` in `src/services/auditService.js`) and endpoint `GET /api/audit/verify` that verifies 100% chain integrity mathematically.
- **Reference Code / Commit:** [`src/services/auditService.js`](file:///c:/Users/MD%20ARSHAD/Desktop/GuardFile/src/services/auditService.js) and [`src/db/schema.sql`](file:///c:/Users/MD%20ARSHAD/Desktop/GuardFile/src/db/schema.sql)

---

### Entry 3: File Upload Validation & MIME Spoofing
- **Date:** 2026-10-20  
- **Prompt:**  
  > *"Set up Multer file upload middleware with validation to accept only PDF, DOCX, and image files."*
- **What it produced:**  
  ```javascript
  const upload = multer({
    fileFilter: (req, file, cb) => {
      const allowed = ['application/pdf', 'image/png', 'image/jpeg'];
      if (allowed.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(new Error('Invalid file type'));
      }
    }
  });
  ```
- **What was wrong with it specifically:**  
  `file.mimetype` is populated directly from the client's HTTP header (`Content-Type: application/pdf`). An attacker can easily upload a compiled Windows executable (`malicious.exe`) or shell script simply by naming it `contract.pdf` and providing a spoofed MIME header. Relying on client-supplied MIME types is a textbook security flaw.
- **What we did instead:**  
  Implemented **Server-Side Magic Byte Signature Inspection** (`src/utils/magicBytes.js` and `src/middleware/fileValidator.js`). The buffer is checked directly on the server:
  - Disallows known binary executable headers (`MZ` for PE executables, `\x7fELF`, Mach-O, `#!/bin/sh`, `<?php`).
  - Verifies format-specific magic bytes (e.g. `%PDF-` `0x25 0x50 0x44 0x46 0x2D` for PDFs, `\x89PNG` for PNGs, `PK\x03\x04` for Office ZIP XML).
  - Rejects disguised files with HTTP 400 Bad Request before writing anything to disk.
- **Reference Code / Commit:** [`src/utils/magicBytes.js`](file:///c:/Users/MD%20ARSHAD/Desktop/GuardFile/src/utils/magicBytes.js)

---

### Entry 4: Path Traversal Defense in Storage Engine
- **Date:** 2026-10-20  
- **Prompt:**  
  > *"Write a secure storage helper that ensures files cannot escape the storage directory via path traversal."*
- **What it produced:**  
  ```javascript
  function resolvePath(filename) {
    const safeName = path.basename(filename);
    return path.join(STORAGE_DIR, safeName);
  }
  ```
- **What was wrong with it specifically:**  
  While `path.basename('../../etc/passwd')` extracts `'passwd'`, it silently mutates the attacker's path and accesses `STORAGE_DIR/passwd` without raising an alarm or logging the attack. Worse, if arbitrary nested paths are passed elsewhere, or if `path.resolve` with user input is used, an attacker could supply `..` sequences to escape the web root.
- **What we did instead:**  
  Built strict defensive path validation in `src/services/storageService.js`:
  1. Detects null bytes (`\0`) and explicitly rejects any path string containing `..`.
  2. Asserts that the normalized absolute path strictly begins with `STORAGE_DIR`.
  3. Throws an explicit `SECURITY ALERT: Path Traversal attempt blocked!` exception and logs the refused event.
- **Reference Code / Commit:** [`src/services/storageService.js`](file:///c:/Users/MD%20ARSHAD/Desktop/GuardFile/src/services/storageService.js)

---

### Entry 5: Database Abstraction & UPDATE Row Count Handling
- **Date:** 2026-10-20  
- **Prompt:**  
  > *"Create a unified database client adapter that wraps both node-postgres and PGlite so tests run without an external database server."*
- **What it produced:**  
  ```javascript
  dbClient = {
    async query(text, params) {
      const result = await pglite.query(text, params);
      return {
        rows: result.rows || [],
        rowCount: result.rows ? result.rows.length : (result.affectedRows || 0)
      };
    }
  };
  ```
- **What was wrong with it specifically:**  
  In PostgreSQL / PGlite, when executing an `UPDATE` statement without a `RETURNING` clause, `result.rows` is an empty array `[]` (which is truthy in JavaScript). Evaluating `result.rows ? result.rows.length : (result.affectedRows || 0)` evaluated to `0`, completely masking `result.affectedRows = 1`. This caused `revokePermission` to mistakenly report `rowCount === 0` and return HTTP 404, breaking the revocation flow during integration testing!
- **What we did instead:**  
  Corrected the row count determination logic:
  ```javascript
  const count = typeof result.affectedRows === 'number'
    ? result.affectedRows
    : (result.rows ? result.rows.length : 0);
  ```
  Additionally, appended `RETURNING id` to the SQL query to ensure unambiguous row returns across both drivers.
- **Reference Code / Commit:** [`src/config/database.js`](file:///c:/Users/MD%20ARSHAD/Desktop/GuardFile/src/config/database.js)

---

## Reusable System Directives & Context Prompts

Across the project, the following guiding security directive was maintained in all AI interactions:

```markdown
SYSTEM CONSTRAINTS (ZERO-TRUST COMPLIANCE):
1. Never hide buttons or rely on client-side routing for security. The server decides every time.
2. File permissions must never be cached in JWT tokens or memory. Real-time DB lookup is required.
3. Every unauthorized read or download attempt must return HTTP 403 and immediately record a READ_DENIED entry in audit_logs with IP address and timestamp.
4. Revocation must take effect immediately on the next millisecond request.
5. The audit trail must be append-only and cryptographically chained.
```
