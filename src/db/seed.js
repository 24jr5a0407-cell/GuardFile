const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const { randomUUID: uuidv4 } = require('crypto');
const { query } = require('../config/database');
const { storeFile } = require('../services/storageService');
const { recordEvent } = require('../services/auditService');

// Stable UUIDs for consistent testing and seeding
const SEED_IDS = {
  admin: '11111111-1111-1111-1111-111111111111',
  alice: '22222222-2222-2222-2222-222222222222',
  bob: '33333333-3333-3333-3333-333333333333',
  charlie: '44444444-4444-4444-4444-444444444444',
  doc1: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  doc2: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  doc3: 'cccccccc-cccc-cccc-cccc-cccccccccccc',
};

async function seed() {
  console.log('[Seed] Seeding database with idempotent users, documents, and permissions...');

  const salt = await bcrypt.genSalt(10);
  const adminHash = await bcrypt.hash('AdminPassword123!', salt);
  const ownerHash = await bcrypt.hash('OwnerPassword123!', salt);
  const viewerHash = await bcrypt.hash('ViewerPassword123!', salt);

  // 1. Upsert Users (Idempotent)
  const users = [
    { id: SEED_IDS.admin, name: 'System Administrator', email: 'admin@trustvault.local', phone: '+15550000001', hash: adminHash, role: 'admin' },
    { id: SEED_IDS.alice, name: 'Alice (Executive HR)', email: 'alice@trustvault.local', phone: '+15550000002', hash: ownerHash, role: 'owner' },
    { id: SEED_IDS.bob, name: 'Bob (Chief Architect)', email: 'bob@trustvault.local', phone: '+15550000003', hash: ownerHash, role: 'owner' },
    { id: SEED_IDS.charlie, name: 'Charlie (Auditor / Viewer)', email: 'charlie@trustvault.local', phone: '+15550000004', hash: viewerHash, role: 'viewer' },
  ];

  for (const u of users) {
    await query(
      `INSERT INTO users (id, name, email, phone, password_hash, role, account_status, terms_accepted)
       VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', TRUE)
       ON CONFLICT (email)
       DO UPDATE SET name = EXCLUDED.name, phone = EXCLUDED.phone, password_hash = EXCLUDED.password_hash, role = EXCLUDED.role, account_status = 'ACTIVE'`,
      [u.id, u.name, u.email, u.phone, u.hash, u.role]
    );
  }

  // Fetch resolved user IDs from database to guarantee FK constraints
  const userRows = (await query('SELECT id, email FROM users')).rows;
  const userMap = {};
  userRows.forEach(r => { userMap[r.email] = r.id; });

  const aliceId = userMap['alice@trustvault.local'];
  const bobId = userMap['bob@trustvault.local'];
  const charlieId = userMap['charlie@trustvault.local'];

  // 2. Sample physical files
  const sample1Content = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (Executive Compensation & Salary Review 2026) /Author (Alice HR) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF', 'utf8');
  const sample2Content = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (TrustVault Zero-Trust Core Architecture Blueprint) /Author (Bob Architect) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF', 'utf8');
  const sample3Content = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (Q3 Confidential Financial Audit Report) /Author (Alice Finance) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF', 'utf8');

  const file1 = await storeFile(sample1Content, 'Board_Compensation_Review_2026.pdf');
  const file2 = await storeFile(sample2Content, 'Zero_Trust_Core_Architecture.pdf');
  const file3 = await storeFile(sample3Content, 'Quarterly_Financial_Ledger_Q3.pdf');

  // 3. Upsert Documents
  const docs = [
    { id: SEED_IDS.doc1, title: 'Board Compensation Review 2026', cat: 'HR / Payroll', file: file1, owner: aliceId },
    { id: SEED_IDS.doc2, title: 'TrustVault Zero-Trust Architecture Blueprint', cat: 'Engineering', file: file2, owner: bobId },
    { id: SEED_IDS.doc3, title: 'Quarterly Financial Ledger Q3', cat: 'Finance', file: file3, owner: aliceId },
  ];

  for (const d of docs) {
    await query(
      `INSERT INTO documents (id, title, category, file_path, file_name, file_size, mime_type, file_hash, owner_id)
       VALUES ($1, $2, $3, $4, $5, $6, 'application/pdf', $7, $8)
       ON CONFLICT (id)
       DO UPDATE SET title = EXCLUDED.title, category = EXCLUDED.category, file_path = EXCLUDED.file_path, file_hash = EXCLUDED.file_hash, owner_id = EXCLUDED.owner_id`,
      [d.id, d.title, d.cat, d.file.storagePath, d.file.fileName, d.file.fileSize, d.file.fileHash, d.owner]
    );
  }

  // 4. Configure Initial Permissions (Idempotent)
  // Grant 1: Bob grants Charlie active READ permission on Document 2 (Architecture Blueprint)
  await query(
    `INSERT INTO document_permissions (document_id, user_id, access_level, is_revoked, granted_at, revoked_at, granted_by)
     VALUES ($1, $2, 'read', FALSE, CURRENT_TIMESTAMP, NULL, $3)
     ON CONFLICT (document_id, user_id)
     DO UPDATE SET access_level = 'read', is_revoked = FALSE, revoked_at = NULL, granted_at = CURRENT_TIMESTAMP`,
    [SEED_IDS.doc2, charlieId, bobId]
  );

  // Grant 2: Alice granted Charlie READ permission on Document 3 (Financial Ledger), but REVOKED IT!
  await query(
    `INSERT INTO document_permissions (document_id, user_id, access_level, is_revoked, granted_at, revoked_at, granted_by)
     VALUES ($1, $2, 'read', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $3)
     ON CONFLICT (document_id, user_id)
     DO UPDATE SET access_level = 'read', is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP`,
    [SEED_IDS.doc3, charlieId, aliceId]
  );

  // Clean any old permissions on Doc 1 for Charlie to guarantee isolation baseline
  await query(
    `DELETE FROM document_permissions WHERE document_id = $1 AND user_id = $2`,
    [SEED_IDS.doc1, charlieId]
  );

  console.log('[Seed] Idempotent seeding complete.');
}

if (require.main === module) {
  seed()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Seed Error]', err);
      process.exit(1);
    });
}

module.exports = { seed, SEED_IDS };
