# TrustVault — Zero-Trust Document Sharing with a Real Audit Trail
**Snovasys Fresher Hiring Challenge 2026 | Solo Engineering Submission**

[![Tests](https://img.shields.io/badge/tests-12%20passed-brightgreen.svg)]()
[![Zero--Trust](https://img.shields.io/badge/architecture-Zero--Trust-blue.svg)]()
[![Audit--Ledger](https://img.shields.io/badge/audit-Cryptographically%20Chained-emerald.svg)]()
[![License](https://img.shields.io/badge/license-MIT-slate.svg)]()

> *"Build a document platform where the wrong person can never read the file, and you can prove who read it."*

---

## 🚀 Live Demo & Seed Accounts

- **Live URL:** [https://trustvault-guardfile.onrender.com](https://trustvault-guardfile.onrender.com) *(or `http://localhost:4000` when running locally)*
- **Interactive Role Switcher:** A one-click Judge Switcher is embedded directly in the top navigation bar of the web application. You can switch between roles in one click to test isolation immediately.

### Seed Credentials

| Role | Name | Email | Password | Pre-Configured Vault State |
|---|---|---|---|---|
| **System Administrator** | CSO Office | `admin@trustvault.local` | `AdminPassword123!` | System-wide audit logs, global security monitoring, zero-trust file restrictions. |
| **Document Owner (HR)** | Alice | `alice@trustvault.local` | `OwnerPassword123!` | Owns *Board Compensation 2026* & *Q3 Financial Ledger*. Revoked Charlie's access on Doc 3. |
| **Document Owner (Eng)** | Bob | `bob@trustvault.local` | `OwnerPassword123!` | Owns *Zero-Trust Core Architecture*. Granted Charlie active read access. |
| **Viewer / Auditor** | Charlie | `charlie@trustvault.local` | `ViewerPassword123!` | Can read Doc 2 (active grant). Blocked from Doc 3 (revoked grant) and Doc 1 (no grant). |

---

## ⚡ Quick Start: Clean Clone Setup

TrustVault is engineered to run seamlessly on **any machine** (Windows, macOS, Linux) with zero prerequisite database setup required.

```bash
# 1. Clone repository
git clone https://github.com/24jr5a0407-cell/GuardFile.git
cd Guardfile

# 2. Install dependencies
npm install

# 3. Run automated security test suite (Runs 12 comprehensive tests)
npm test

# 4. Start the TrustVault server
npm start
```
Open **`http://localhost:4000`** in your browser.

> **Database Note:** TrustVault ships with an embedded PostgreSQL engine (`PGlite`) enabled out-of-the-box in development. When deploying to production with an external PostgreSQL server (e.g. AWS RDS, Supabase, Neon, Railway), simply supply `DATABASE_URL=postgres://...` in `.env`. The exact same PostgreSQL migrations run identically.

---

## 🛡️ The 3 Non-Negotiable Standards & Implementation Proofs

### Standard 1: Server-Side Authorization Decides Every Time
- **The Principle:** A document is reachable *only* by someone who was explicitly granted it. Not "the button is hidden", not "the page checks". Through any route at all, including ones you did not think of.
- **Implementation:**
  1. No file permissions are ever stored in client JWT tokens or client state.
  2. The backend middleware `authorizeDocument('read' | 'edit')` in `src/middleware/authorize.js` intercepts all download and preview routes (`/api/documents/:id/download`, `/api/documents/:id/preview`).
  3. It executes a real-time indexed database query against `document_permissions` (`document_id = $1 AND user_id = $2 AND is_revoked = FALSE`).
  4. Non-owners without an active grant are immediately returned `HTTP 403 Forbidden`. Even Administrators attempting to download an ungranted document receive `403 Forbidden`!
- **Proof:** Run `npm run test:security`.

### Standard 2: Provable, Unalterable Audit Trail
- **The Principle:** You can prove who reached it afterwards from the record, including attempts that were refused. An audit trail that can be quietly altered is not evidence.
- **Implementation:**
  1. **Refusal Logging:** Every 403 / 404 access refusal writes an immutable `READ_DENIED` entry to `audit_logs` recording the actor ID, target document ID, timestamp, and client IP address.
  2. **Database Immutability Trigger:** In PostgreSQL, the trigger `trg_audit_logs_immutable` executes `prevent_audit_log_tampering()` which raises an uncatchable SQL exception on any `UPDATE` or `DELETE` attempt.
  3. **Cryptographic SHA-256 Hash Chaining:** Every audit entry calculates:
     $$\text{entry\_hash} = \text{SHA-256}(\text{id} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{target} \parallel \text{ip} \parallel \text{status} \parallel \text{prev\_hash})$$
     Altering or deleting a single row breaks the cryptographic chain. The built-in endpoint `GET /api/audit/verify` cryptographically verifies the entire ledger from Genesis to head.
- **Proof:** In the UI, click **"Verify Ledger Chain"** or run `npm test` (`tests/audit.test.js`).

### Standard 3: Taking Access Away Works Immediately
- **The Principle:** Whatever you have issued to that person before that moment stops working.
- **Implementation:**
  1. Revocation executes `UPDATE document_permissions SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP WHERE document_id = $1 AND user_id = $2`.
  2. Because access checks query the database on every request, revocation terminates access across all active sessions in `< 1 millisecond`.
  3. The very next millisecond request is blocked with `403 Forbidden` and logged as `READ_DENIED`.
- **Proof:** `tests/security.test.js` &rarr; `STANDARD 3: Instant Revocation`.

---

## 📁 Repository Structure

```
trustvault-guardfile/
├── THREATS.md              # Threat Model, STRIDE matrix, 12 attack vectors & accepted risks
├── PROMPTS.md              # AI Engineering Log: 5 dated entries detailing AI mistakes caught
├── API.md                  # Complete REST API specification with role permissions
├── server.js               # Main Express entrypoint with CSP & rate limiters
├── src/
│   ├── config/
│   │   ├── database.js     # Unified PostgreSQL driver (Supports Pool & PGlite)
│   │   └── email.js        # Nodemailer transport (guardfile@gmail.com)
│   ├── db/
│   │   ├── schema.sql      # Production PostgreSQL schema with triggers & indices
│   │   ├── seed.js         # Idempotent seed script (Admin, Alice, Bob, Charlie)
│   │   └── migrate.js      # Migration runner
│   ├── middleware/
│   │   ├── auth.js         # JWT verification & session injection
│   │   ├── rbac.js         # Role-based access control (admin, owner, viewer)
│   │   ├── authorize.js    # Strict Zero-Trust object-level authorization middleware
│   │   └── fileValidator.js# Magic bytes, MIME type, extension & path traversal validator
│   ├── routes/
│   │   ├── authRoutes.js   # Login, registration, 2FA/OTP dispatch & verification
│   │   ├── documentRoutes.js # Upload, search, download stream, preview, delete
│   │   ├── permissionRoutes.js # Grant & Instant Revocation
│   │   └── auditRoutes.js  # Tamper-evident audit logs & cryptographic verification
│   ├── services/
│   │   ├── auditService.js # Cryptographic Merkle hash chaining & physical ledger
│   │   ├── storageService.js # Isolated storage outside web root & path traversal defense
│   │   └── otpService.js   # 6-digit OTP delivery via Nodemailer with dev fallback
│   └── utils/
│       ├── crypto.js       # SHA-256, HMAC, secure OTP generator
│       └── magicBytes.js   # Binary file header signature checker (MZ, ELF, PDF, PNG)
├── secure_storage/         # Isolated directory outside web root for confidential files
├── public/                 # Static frontend (UI inspired by modern dashboard design)
│   ├── index.html          # Clean responsive dashboard
│   ├── css/styles.css      # Custom styling & animations
│   └── js/                 # Client controllers (auth, documents, audit, app)
└── tests/
    ├── security.test.js    # Zero-trust enforcement, user isolation, instant revocation
    ├── upload.test.js      # MIME spoofing, magic byte validation, path traversal defense
    └── audit.test.js       # SQL trigger immutability & cryptographic chain integrity
```

---

## 🧪 Automated Test Suite Coverage

Run the tests at any time with:
```bash
npm test
```

### Test Results Breakdown:
- **`tests/security.test.js`**
  - `STANDARD 1`: Proves Charlie (Viewer) cannot download Alice's document without a grant (User Isolation).
  - `STANDARD 2`: Proves refused access attempt is permanently recorded in `audit_logs` with actor and IP.
  - `STANDARD 3`: Proves Instant Revocation terminates access immediately on subsequent requests.
  - `Admin Segregation`: Proves Admin role cannot bypass document ACL without an explicit grant.
  - `Privilege Escalation`: Proves Viewer cannot grant permissions or delete documents.
- **`tests/upload.test.js`**
  - `MIME Spoofing Defense`: Disguised Windows `.exe` binary with `.pdf` extension is detected and rejected.
  - `Path Traversal Defense`: Sequences like `..` in filenames are rejected.
  - `Storage Isolation`: Asserts `resolveSecurePath` blocks attempts escaping `secure_storage`.
  - `Legitimate Upload`: Verifies valid `%PDF-` document is accepted and hashed.
- **`tests/audit.test.js`**
  - `SQL Trigger Immutability`: Direct `UPDATE` on `audit_logs` raises a `SECURITY VIOLATION` error.
  - `SQL Trigger Immutability`: Direct `DELETE` on `audit_logs` raises a `SECURITY VIOLATION` error.
  - `Cryptographic Chain`: Mathematical verification of 100% unbroken SHA-256 block links.

---

## 📝 Short Engineering Write-up

### 1. What We Built
We built **TrustVault**, an enterprise-grade document sharing system designed around zero-trust authorization and cryptographic non-repudiation:
- Real-time server-side object authorization (no stale permission caches).
- Instant permission revocation ($< 1$ millisecond effect).
- Append-only audit trail protected by both PostgreSQL database triggers and SHA-256 cryptographic chaining.
- Strict server-side magic byte inspection defending against disguised executables and MIME spoofing.
- 2FA / OTP verification using `guardfile@gmail.com` via Nodemailer.
- High-polish modern dashboard interface (inspired by clean SaaS portal aesthetics) with live search, filters, instant revoke controls, and a quick Judge Role Switcher.

### 2. What We Deliberately Did NOT Build and Why
1. **No Client-Side Permission Caching / Scoped JWTs:** Many systems put document IDs inside JWT tokens or use long-lived pre-signed S3 URLs. We deliberately rejected this because it makes instant revocation impossible without complex token blacklisting infrastructure. Querying indexed database permissions on each request costs $< 1$ ms and guarantees immediate revocation.
2. **No Intrusive Client-Side DRM:** We did not build browser-blocking DRM or disable print-screen keys. Once bits reach a client display, physical photography cannot be prevented by software. Instead, TrustVault focuses on complete, cryptographically verified accountability: proving *who* accessed the document and *when*.
3. **No Soft-Deletes for Audit Logs:** Audit logs have no `is_deleted` column and no API deletion endpoint. Audit records can never be deleted through the application.

### 3. Our Permission Model in Our Own Words
TrustVault uses a **Dual-Layer Access Control Model**:
- **Layer 1: Role-Based Access Control (RBAC):** Governs system capabilities (`admin`, `owner`, `viewer`). Owners can upload and manage documents. Viewers can only consume what is shared with them. Admins monitor system health, inspect global audit trails, and manage user accounts.
- **Layer 2: Zero-Trust Object-Level Access Control (ACL):** Governs file byte access. The document owner possesses inherent rights. All other users—including Administrators—must hold an active, unrevoked record in `document_permissions` (`access_level IN ('read', 'edit')`, `is_revoked = FALSE`). The server evaluates this in real time on every request.

### 4. How We Used AI and Where It Was Wrong
We used AI coding tools for rapid scaffolding, test composition, and UI drafting. However, as documented in [`PROMPTS.md`](file:///c:/Users/MD%20ARSHAD/Desktop/GuardFile/PROMPTS.md), the AI repeatedly offered insecure or flawed suggestions:
- It attempted to cache document permissions inside JWT tokens, which would have destroyed the instant revocation requirement.
- It created an audit log deletion endpoint for "maintenance", which would have broken audit trail integrity.
- It validated uploads using `file.mimetype`, which trivially succumbs to MIME spoofing.
- It used `path.basename` naively, masking path traversal attacks rather than detecting and logging them.
- It wrote an incorrect row count check for PostgreSQL `UPDATE` statements, causing revocation to report false 404s.
Catching and replacing these flaws with robust security architectures was the core engineering effort.

### 5. What is Unfinished / Future Roadmap
- **Hardware Security Module (HSM) / KMS Key Encryption:** Documents are currently hashed with SHA-256 and stored outside the web root. Adding AES-256-GCM envelope encryption with keys managed in AWS KMS or HashiCorp Vault is the natural next step.
- **Automated Anomaly Detection:** An automated engine that flags users generating more than 5 `READ_DENIED` events in 10 minutes and triggers an automatic account lock.
