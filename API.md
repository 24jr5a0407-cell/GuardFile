# TrustVault — REST API Specification & Authorization Matrix
**Version:** 1.0.0  
**Base URL:** `http://localhost:4000/api`  
**Security Standard:** Zero-Trust Object-Level Enforcement & Cryptographic Auditing

---

## 1. Authentication Endpoints (`/api/auth`)

### `POST /api/auth/register`
- **Description:** Registers a new user account.
- **Allowed Roles:** Public (Unauthenticated). Self-registration is restricted to role `viewer` (or `owner` if selected); `admin` role cannot be self-assigned.
- **Request Body:**
  ```json
  {
    "name": "Jane Doe",
    "email": "jane@company.com",
    "password": "SecurePassword123!",
    "role": "viewer"
  }
  ```
- **Responses:**
  - `201 Created`: `{ "message": "Account created successfully", "user": { ... } }`
  - `400 Bad Request`: Missing required fields.
  - `409 Conflict`: Email already exists.

---

### `POST /api/auth/login`
- **Description:** Authenticates credentials and issues a signed JWT token or triggers 2FA/OTP dispatch.
- **Allowed Roles:** Public.
- **Request Body:**
  ```json
  {
    "email": "alice@trustvault.local",
    "password": "OwnerPassword123!",
    "require2fa": false
  }
  ```
- **Audit Effect:** Logs `AUTH_LOGIN_SUCCESS` or `AUTH_LOGIN_FAILED` with client IP address.
- **Responses:**
  - `200 OK` (Direct): `{ "token": "ey...", "user": { "id": "...", "name": "...", "email": "...", "role": "owner" } }`
  - `200 OK` (2FA Required): `{ "require2FA": true, "userId": "...", "message": "Security code dispatched" }`
  - `401 Unauthorized`: Invalid credentials.

---

### `POST /api/auth/verify-otp`
- **Description:** Validates 6-digit one-time password and returns JWT session token. Burns OTP immediately (anti-replay).
- **Allowed Roles:** Public (with valid `userId` from login step).
- **Request Body:**
  ```json
  {
    "userId": "uuid-v4-string",
    "otpCode": "849201"
  }
  ```
- **Responses:**
  - `200 OK`: `{ "token": "ey...", "user": { ... } }`
  - `401 Unauthorized`: Expired or incorrect OTP code.

---

### `GET /api/auth/me`
- **Description:** Returns profile and active role of currently authenticated user.
- **Allowed Roles:** Any Authenticated User (`admin`, `owner`, `viewer`).
- **Header:** `Authorization: Bearer <token>`
- **Responses:**
  - `200 OK`: `{ "user": { "id": "...", "email": "...", "role": "..." } }`
  - `401 Unauthorized`: Missing or invalid token.

---

### `GET /api/auth/users`
- **Description:** Retrieves user directory for document sharing recipient selection.
- **Allowed Roles:** Any Authenticated User (`admin`, `owner`, `viewer`).
- **Responses:**
  - `200 OK`: `{ "users": [ { "id": "...", "name": "...", "email": "...", "role": "..." } ] }`

---

## 2. Document Endpoints (`/api/documents`)

### `POST /api/documents/upload`
- **Description:** Secure document upload. Inspects raw magic byte signatures, validates MIME type and file extension, hashes content with SHA-256, and stores in isolated `/secure_storage`.
- **Allowed Roles:** Document Owners (`owner`) and System Administrators (`admin`). Viewers are blocked.
- **Headers:** `Authorization: Bearer <token>`, `Content-Type: multipart/form-data`
- **Form Data:**
  - `title`: string (Required)
  - `category`: string (e.g. `HR / Payroll`, `Engineering`, `Finance`, `Legal`)
  - `file`: binary buffer (Strictly validated: PDF, DOCX, XLSX, TXT, PNG, JPG, CSV; max 15MB)
- **Audit Effect:** Records `UPLOAD` in audit ledger with SHA-256 file hash and IP.
- **Responses:**
  - `201 Created`: `{ "message": "Document uploaded and registered securely.", "document": { ... } }`
  - `400 Bad Request`: Disguised executable, magic byte mismatch, invalid extension, or path traversal detected.
  - `403 Forbidden`: User role is `viewer`.

---

### `GET /api/documents`
- **Description:** Lists documents accessible to the caller. Zero data leakage: Users ONLY receive metadata for documents they own or have an active, unrevoked permission grant for.
- **Allowed Roles:** Any Authenticated User (`admin`, `owner`, `viewer`).
- **Query Parameters:**
  - `q`: Search string (title or filename)
  - `category`: Filter by category
  - `owner`: Filter by owner name or email
  - `fromDate`, `toDate`: ISO date bounds
- **Responses:**
  - `200 OK`: `{ "documents": [ { "id": "...", "title": "...", "category": "...", "file_hash": "...", "user_access_level": "read|edit|owner" } ] }`

---

### `GET /api/documents/:id`
- **Description:** Retrieves metadata for a specific document.
- **Allowed Roles:** Document Owner OR User with active, unrevoked grant on `:id`.
- **Zero-Trust Enforcement:** Checked via `authorizeDocument('read')`. If unauthorized, returns HTTP 403 and writes `READ_DENIED` to audit trail.
- **Responses:**
  - `200 OK`: `{ "document": { ... } }`
  - `403 Forbidden`: User does not hold an active grant.
  - `404 Not Found`: Document does not exist.

---

### `GET /api/documents/:id/download`
- **Description:** Authenticated binary streaming file download.
- **Allowed Roles:** Document Owner OR User with active, unrevoked grant on `:id`.
- **Zero-Trust Enforcement:** Real-time query to `document_permissions`.
  - If grant active: Records `READ_SUCCESS` in audit trail and pipes file stream from isolated storage outside web root.
  - If grant revoked or absent: Immediately records `READ_DENIED` with client IP and returns `403 Forbidden`.
- **Response Headers:**
  - `Content-Disposition: attachment; filename="..."`
  - `Content-Type: application/pdf` (or mime type)
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store, private`

---

### `GET /api/documents/:id/preview`
- **Description:** In-browser inline preview stream.
- **Allowed Roles:** Document Owner OR User with active, unrevoked grant on `:id`.
- **Responses:**
  - `200 OK`: Inline stream (`Content-Disposition: inline`).
  - `403 Forbidden`: Access denied (logged in audit trail).

---

### `PUT /api/documents/:id`
- **Description:** Modifies document title or category.
- **Allowed Roles:** Document Owner OR User with active `edit` grant.
- **Audit Effect:** Records `EDIT` in audit ledger with previous and updated values.
- **Responses:**
  - `200 OK`: `{ "message": "Updated", "document": { ... } }`
  - `403 Forbidden`: User holds only `read` grant or is unauthorized.

---

### `DELETE /api/documents/:id`
- **Description:** Permanently deletes the document record and unlinks the physical asset from disk.
- **Allowed Roles:** Document Owner (or Admin).
- **Audit Effect:** Records `DELETE` in audit ledger with destroyed file hash.
- **Responses:**
  - `200 OK`: `{ "message": "Document and physical asset permanently destroyed." }`
  - `403 Forbidden`: Non-owner attempting deletion.

---

## 3. Permission & Revocation Endpoints (`/api/permissions`)

### `POST /api/permissions/grant`
- **Description:** Document owner grants granular `read` or `edit` permission to a named user.
- **Allowed Roles:** Document Owner only.
- **Request Body:**
  ```json
  {
    "documentId": "uuid-v4",
    "userId": "uuid-v4",
    "accessLevel": "read"
  }
  ```
- **Audit Effect:** Records `GRANT` in audit ledger.
- **Responses:**
  - `200 OK`: `{ "message": "Successfully granted READ access", "grant": { ... } }`
  - `403 Forbidden`: Caller is not document owner.
  - `404 Not Found`: Document or recipient user not found.

---

### `POST /api/permissions/revoke`
- **Description:** Document owner immediately revokes access from a named user.
- **Allowed Roles:** Document Owner only.
- **Enforcement:** Sets `is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP`. Takes effect instantly on all subsequent requests across all active sessions.
- **Request Body:**
  ```json
  {
    "documentId": "uuid-v4",
    "userId": "uuid-v4",
    "reason": "Audit window concluded"
  }
  ```
- **Audit Effect:** Records `REVOKE` in audit ledger with timestamp and reason.
- **Responses:**
  - `200 OK`: `{ "message": "Access immediately revoked...", "revocation": { ... } }`
  - `403 Forbidden`: Caller is not document owner.
  - `404 Not Found`: No active grant found to revoke.

---

### `GET /api/permissions/document/:id`
- **Description:** Retrieves all active and revoked grants for a document.
- **Allowed Roles:** Document Owner or Administrator.
- **Responses:**
  - `200 OK`: `{ "permissions": [ { "id": "...", "user_name": "...", "access_level": "read", "is_revoked": false } ] }`

---

## 4. Audit Trail & Verification Endpoints (`/api/audit`)

### `GET /api/audit`
- **Description:** Retrieves tamper-evident audit logs.
- **Allowed Roles:**
  - System Administrator: Can view system-wide audit trail.
  - Document Owner: Can view audit records targeting their owned documents.
  - Viewers: Blocked (`403 Forbidden`).
- **Query Parameters:** `status` (`SUCCESS` / `DENIED`), `action`, `actor`, `target`, `fromDate`, `toDate`, `limit`, `offset`.
- **Responses:**
  - `200 OK`: `{ "total": 42, "logs": [ { "id": "...", "timestamp": "...", "actor_email": "...", "action": "READ_DENIED", "ip_address": "...", "status": "DENIED", "prev_hash": "...", "entry_hash": "..." } ] }`

---

### `GET /api/audit/verify`
- **Description:** Cryptographically re-computes and validates the entire SHA-256 Merkle/hash chain from Genesis block to latest entry.
- **Allowed Roles:** Any Authenticated User.
- **Responses:**
  - `200 OK`:
    ```json
    {
      "valid": true,
      "totalRecords": 42,
      "headHash": "ab00d1668fae7cce84d3e275cab15e3ccdce5d76075ab7f6999a948274eea5d5",
      "message": "Cryptographic audit ledger verified. 100% integrity confirmed."
    }
    ```
  - `500 Server Error`: Chain broken / tampering detected with specific record ID.

---

### `GET /api/audit/stats`
- **Description:** Summary metrics for the administrative dashboard overview.
- **Allowed Roles:** Any Authenticated User.
- **Responses:**
  - `200 OK`: `{ "totalDocuments": 3, "activePermissions": 1, "revokedPermissions": 1, "deniedAccessAttempts": 2, "totalAuditTransactions": 14 }`
