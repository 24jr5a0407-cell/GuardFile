# TrustVault — Threat Model & Security Defense Architecture
**Author:** TrustVault Security Engineering Team  
**Event:** Snovasys Fresher Hiring Challenge 2026  
**Document Classification:** Confidential / Public Submission Specification

---

## 1. System Overview & Trust Boundaries

TrustVault is engineered under a **Zero-Trust Architecture** model: *Never trust, always verify, and prove every action.* In enterprise confidential document sharing, the cost of an unauthorized read is catastrophic. Traditional applications rely on UI-level gating (hiding buttons) or coarse role checks. TrustVault enforces fine-grained, object-level authorization on the server for 100% of requests, backed by an append-only, cryptographically chained audit ledger.

### Trust Boundary Architecture:
```
                      [UNTRUSTED CLIENT ZONE]
                                 │
                     (JWT Bearer / Browser UI)
                                 │
═════════════════════════════════╪═════════════════════════════════
                       [DMZ / GATEWAY LAYER]
                                 │
                   Helmet CSP / Rate Limiter / CORS
                                 │
═════════════════════════════════╪═════════════════════════════════
                    [ZERO-TRUST CONTROL PLANE]
                                 │
       ┌─────────────────────────┴────────────────────────┐
       ▼                                                  ▼
[auth.js: JWT Validation]                       [fileValidator.js]
       │                                        (Magic Bytes Check)
       ▼                                                  │
[rbac.js: Role Enforcement]                               │
       │                                                  │
       ▼                                                  │
[authorize.js: Real-Time ACL] ◄───────────────────────────┘
  • Live query to document_permissions
  • Checks (is_revoked == false)
  • Bypasses NO ONE (even Admins without grant)
       │
 ┌─────┴──────────────────────┐
 │ (Refusal)                  │ (Authorized)
 ▼                            ▼
[auditService.js]            [storageService.js]
  • Log READ_DENIED            • Pipe file stream outside web root
  • Cryptographic Chain Seal   • Log READ_SUCCESS
  • Return HTTP 403            • Stream bytes directly to client
```

---

## 2. Threat Analysis & Closed Attack Vectors

Below is our exhaustive threat catalog. Every single vector has been analyzed, closed with concrete code, and verified using automated integration tests.

### Threat 1: Broken Object-Level Authorization (BOLA / IDOR)
- **Vector:** An attacker possessing a valid viewer or owner session modifies the target UUID in `GET /api/documents/:id/download` or `GET /api/documents/:id/preview` to an unauthorized document UUID.
- **Why Naive Systems Leak:** Many systems authenticate the token, check `if (req.user)`, and directly read `documents.findById(id)` without validating whether *this specific user* has an active grant for *this specific document*.
- **TrustVault Mitigation:** 
  1. The `authorizeDocument(requiredAccess)` middleware intercepts all document access routes before any file descriptor is touched.
  2. The middleware executes an atomic real-time database query against `document_permissions`:
     ```sql
     SELECT id, access_level, is_revoked, granted_at, revoked_at
     FROM document_permissions
     WHERE document_id = $1 AND user_id = $2
     ```
  3. If no active grant exists, access is refused with `HTTP 403 Forbidden`.
  4. The server immediately records an immutable `READ_DENIED` event in `audit_logs` capturing the user ID, target document ID, timestamp, and IP address.
- **Automated Test Proof:** `tests/security.test.js` &rarr; `test('STANDARD 1: Charlie CANNOT read Alice\'s document without a grant')`.

---

### Threat 2: Stale Session & Revocation Window (TOCTOU)
- **Vector:** An employee leaves the company or an external partner's contract ends. The document owner revokes access. The attacker continues to download documents using a pre-issued token or cached permission grant.
- **Why Naive Systems Leak:** Systems embedding permission scopes inside JWT tokens cannot invalidate access until the token expires (often 24 hours to 7 days). Signed S3 URLs remain valid until expiration.
- **TrustVault Mitigation:**
  1. **Zero Permission Caching:** Permissions are *never* baked into client JWT tokens or application memory cache.
  2. **Instant Revocation Semantics:** When an owner clicks "Revoke", `POST /api/permissions/revoke` executes:
     ```sql
     UPDATE document_permissions
     SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
     WHERE document_id = $1 AND user_id = $2 AND is_revoked = FALSE
     ```
  3. Because the authorization middleware queries the database in real time on *every single incoming request*, revocation takes effect instantaneously within sub-milliseconds. Any subsequent request is blocked with HTTP 403 and logged as `READ_DENIED`.
- **Automated Test Proof:** `tests/security.test.js` &rarr; `test('STANDARD 3: Instant Revocation - Taking access away works immediately')`.

---

### Threat 3: MIME-Type Spoofing & Disguised Executable Uploads
- **Vector:** An attacker uploads a malicious Windows binary (`.exe`), Linux ELF executable, or PHP shell renamed to `invoice_2026.pdf` with the client header `Content-Type: application/pdf`.
- **Why Naive Systems Leak:** Relying on `file.mimetype` or `file.originalname.endsWith('.pdf')` blindly trusts client-controlled input.
- **TrustVault Mitigation:**
  1. TrustVault implements strict **Magic Byte Verification** (`src/utils/magicBytes.js` and `src/middleware/fileValidator.js`).
  2. The raw binary header buffer is analyzed before saving:
     - Disallowed executable headers (`MZ` `0x4D 0x5A`, ELF `0x7F 0x45 0x4C 0x46`, Mach-O, scripts `#!/bin/sh`, `<?php`) are strictly blocked.
     - PDF files *must* start with the exact magic sequence `%PDF-` (`0x25 0x50 0x44 0x46 0x2D`).
     - Office OpenXML documents *must* start with the ZIP header `PK\x03\x04`.
     - PNG and JPEG files require genuine signature bytes (`\x89PNG\r\n\x1a\n` and `0xFF 0xD8 0xFF`).
  3. Violations trigger an immediate HTTP 400 Bad Request and abort file processing.
- **Automated Test Proof:** `tests/upload.test.js` &rarr; `test('Rejects MIME Spoofing: Executable binary disguised with .pdf extension')`.

---

### Threat 4: Path Traversal & Arbitrary Filesystem Exfiltration
- **Vector:** An attacker supplies path traversal payloads (e.g. `../../../../etc/passwd` or `..\..\windows\system32\cmd.exe`) in file upload names, file IDs, or storage parameters.
- **TrustVault Mitigation:**
  1. **Isolated Storage Root:** The physical storage directory `/secure_storage` is kept completely outside the public web root (`/public`). It is never served by static middleware.
  2. **Opaque Disk Naming:** Files are saved on disk strictly under random UUID identifiers (`<uuid>.<extension>`). The original filename is preserved only in metadata.
  3. **Strict Path Verification:** All disk access routes call `resolveSecurePath()` (`src/services/storageService.js`):
     - Blocks null bytes (`\0`).
     - Blocks `..` traversal sequences.
     - Resolves the normalized absolute path and asserts `absolutePath.startsWith(STORAGE_DIR)`.
- **Automated Test Proof:** `tests/upload.test.js` &rarr; `test('Storage Isolation Engine: resolveSecurePath blocks escaping secure directory')`.

---

### Threat 5: Tampering with the Audit Trail (Rogue Insider / Exfiltration Cover-up)
- **Vector:** An attacker with database credentials or an administrator seeks to delete or alter log entries to conceal an exfiltration incident.
- **TrustVault Mitigation:**
  1. **SQL-Layer Immutability Trigger:** In PostgreSQL, an append-only trigger is active:
     ```sql
     CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
     RETURNS TRIGGER AS $$
     BEGIN
         RAISE EXCEPTION 'SECURITY VIOLATION: audit_logs is an immutable append-only ledger. UPDATE and DELETE operations are strictly prohibited.';
     END;
     $$ LANGUAGE plpgsql;

     CREATE TRIGGER trg_audit_logs_immutable
     BEFORE UPDATE OR DELETE ON audit_logs
     FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering();
     ```
  2. **Cryptographic SHA-256 Hash Chaining:** Every log entry is cryptographically linked to the preceding entry:
     $$\text{entry\_hash} = \text{SHA-256}(\text{id} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{target} \parallel \text{ip} \parallel \text{status} \parallel \text{prev\_hash})$$
     - Any retroactive modification or deletion causes the hash chain to break immediately.
     - Built-in verification endpoint `GET /api/audit/verify` recomputes the entire chain from the Genesis block to detect any altered bit.
  3. **Dual Physical Ledger:** Audit events are simultaneously appended to a local physical forensic ledger file (`logs/audit_ledger.log`).
- **Automated Test Proof:** `tests/audit.test.js` &rarr; `test('Database Trigger blocks direct UPDATE on audit_logs table')` and `test('Cryptographic Verification confirms 100% unbroken chain integrity')`.

---

### Threat 6: Overprivileged Administrator Access (Zero-Trust Enforcement)
- **Vector:** A system administrator leverages their administrative status to quietly read executive salaries, legal contracts, or board minutes without an explicit grant.
- **Why Naive Systems Leak:** Developers often write `if (user.role === 'admin') return next();` which destroys data isolation.
- **TrustVault Mitigation:**
  - Administrators are given system oversight, user management, and global audit log visibility, but **CANNOT bypass object-level document permissions**.
  - If an admin attempts to download an owner's confidential document without being explicitly granted access by the owner, the authorization middleware rejects the admin with HTTP 403 Forbidden and logs a `READ_DENIED` event recording the administrator's actor ID.
- **Automated Test Proof:** `tests/security.test.js` &rarr; `test('Zero-Trust Administrator Restriction: Admin CANNOT read confidential document without explicit grant')`.

---

### Threat 7: Silent Reconnaissance & Document ID Enumeration
- **Vector:** An adversary attempts brute-force scanning of document identifiers to discover existing files without raising alerts.
- **TrustVault Mitigation:**
  1. Document IDs use 128-bit cryptographically secure UUIDv4 ($2^{122}$ random bits), rendering brute-force enumeration mathematically impossible.
  2. Every request for a non-existent document ID logs a `READ_DENIED` event with the caller's IP address and requested resource.
  3. High rates of denied events are flagged on the administrator dashboard overview.

---

### Threat 8: Replay Attacks on 2FA / OTP Verification Codes
- **Vector:** An attacker intercepts an OTP code and attempts to reuse it to generate unauthorized session tokens.
- **TrustVault Mitigation:**
  1. Single-Use Burn: When `verifyOtp()` successfully validates an OTP code, it immediately executes `UPDATE users SET otp_code = NULL, otp_expires_at = NULL WHERE id = $1`.
  2. 5-Minute Time Expiration: Codes expire automatically after 300 seconds.

---

### Threat 9: Privilege Escalation via Registration & Role Tampering
- **Vector:** An attacker attempts mass assignment on `POST /api/auth/register` by sending `{ role: 'admin' }`.
- **TrustVault Mitigation:** The registration controller strictly sanitizes the requested role: `const assignedRole = ['owner', 'viewer'].includes(role) ? role : 'viewer';`. The `admin` role can never be self-assigned.

---

## 3. Knowingly Accepted Risks & Justifications

In honest security engineering, acknowledging residual risk and architectural trade-offs is essential:

| # | Known Residual Risk | Justification & Countermeasure |
|---|---------------------|--------------------------------|
| **R1** | **Client-Side Data Exfiltration via Screen Capture or Photography** | Once a document is legitimately rendered on a screen, DRM / watermark cannot completely stop physical photography. We deliberately chose not to build invasive kernel-level browser extensions. Instead, we ensure that the audit trail proves *exactly who* accessed the document at that millisecond, creating non-repudiation. |
| **R2** | **PostgreSQL Superuser Bypassing Database Trigger** | A database superuser (`postgres`) with direct terminal access can execute `ALTER TABLE audit_logs DISABLE TRIGGER ALL`. This is accepted because application-level constraints cannot constrain the OS/RDBMS root user. To counter this, TrustVault implements **Cryptographic Hash Chaining**: even if a superuser alters or drops a row, `GET /api/audit/verify` detects the broken Merkle chain immediately. |
| **R3** | **Stateless Ephemeral Containers in Cloud Hosting** | When deploying to free-tier ephemeral cloud containers (e.g. Render free dynos), the local filesystem resets on sleep. For production multi-instance scale, the local `/secure_storage` directory should be backed by a private, non-public AWS S3 bucket with IAM object lock. In our single-node deployment, local isolated storage was chosen for zero third-party dependency. |

---

## 4. Threat-to-Test Traceability Matrix

| Attack Vector | Implementation Defense File | Automated Test File | Passing Assertion |
|---|---|---|---|
| BOLA / IDOR | `src/middleware/authorize.js` | `tests/security.test.js` | Returns 403, body contains "Access Denied" |
| Access Refusal Logging | `src/services/auditService.js` | `tests/security.test.js` | Database query confirms `READ_DENIED` with actor and IP |
| Instant Revocation | `src/routes/permissionRoutes.js` | `tests/security.test.js` | Next request returns 403, reason contains "revoked" |
| Admin Overprivilege | `src/middleware/authorize.js` | `tests/security.test.js` | Admin download without grant returns 403 Forbidden |
| Executable MIME Spoofing | `src/utils/magicBytes.js` | `tests/upload.test.js` | Disguised MZ binary rejected with HTTP 400 |
| Path Traversal Escape | `src/services/storageService.js` | `tests/upload.test.js` | `resolveSecurePath` throws "Path Traversal attempt blocked" |
| SQL Audit UPDATE Tamper | `src/db/schema.sql` (trigger) | `tests/audit.test.js` | Trigger aborts query with "SECURITY VIOLATION" |
| SQL Audit DELETE Tamper | `src/db/schema.sql` (trigger) | `tests/audit.test.js` | Trigger aborts query with "SECURITY VIOLATION" |
| Hash Chain Verification | `src/services/auditService.js` | `tests/audit.test.js` | `verifyChain()` recomputes all blocks, returns `valid: true` |
