const request = require('supertest');
const { app } = require('../server');
const { query } = require('../src/config/database');
const { migrate } = require('../src/db/migrate');
const { seed, SEED_IDS } = require('../src/db/seed');

let adminToken;
let aliceToken; // Owner
let bobToken;   // Owner
let charlieToken; // Viewer
let aliceDocId = SEED_IDS.doc1;
let bobDocId = SEED_IDS.doc2;

beforeAll(async () => {
  process.env.NODE_ENV = 'test';
  await migrate();
  await seed();

  // 1. Log in as Alice (Owner)
  const aliceRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'alice@trustvault.local', password: 'OwnerPassword123!' });
  aliceToken = aliceRes.body.token;

  // 2. Log in as Bob (Owner)
  const bobRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'bob@trustvault.local', password: 'OwnerPassword123!' });
  bobToken = bobRes.body.token;

  // 3. Log in as Charlie (Viewer)
  const charlieRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'charlie@trustvault.local', password: 'ViewerPassword123!' });
  charlieToken = charlieRes.body.token;

  // 4. Log in as Admin
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'AdminPassword123!' });
  adminToken = adminRes.body.token;
});

describe('Zero-Trust Document Security & Authorization Enforcement', () => {

  test('STANDARD 1: Charlie CANNOT read Alice\'s document without a grant (User Isolation)', async () => {
    // Attempt to download Alice's document directly using Charlie's token
    const res = await request(app)
      .get(`/api/documents/${aliceDocId}/download`)
      .set('Authorization', `Bearer ${charlieToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Access Denied');
  });

  test('STANDARD 2: Refused access attempt is permanently recorded in audit_logs with IP and actor', async () => {
    // Query audit logs to prove READ_DENIED was recorded
    const logsRes = await query(
      "SELECT * FROM audit_logs WHERE action = 'READ_DENIED' AND target_resource = $1 ORDER BY timestamp DESC LIMIT 1",
      [`document:${aliceDocId}`]
    );

    expect(logsRes.rows.length).toBeGreaterThan(0);
    const log = logsRes.rows[0];
    expect(log.status).toBe('DENIED');
    expect(log.actor_email).toBe('charlie@trustvault.local');
    expect(log.action).toBe('READ_DENIED');
  });

  test('STANDARD 3: Instant Revocation - Taking access away works immediately on subsequent requests', async () => {
    // Step 1: Alice grants Charlie read access to her document
    const grantRes = await request(app)
      .post('/api/permissions/grant')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({
        documentId: aliceDocId,
        userEmail: 'charlie@trustvault.local',
        accessLevel: 'read',
      });

    expect(grantRes.status).toBe(200);
    expect(grantRes.body.grant.isRevoked).toBe(false);

    // Step 2: Charlie downloads successfully with active grant
    const authorizedDownload = await request(app)
      .get(`/api/documents/${aliceDocId}/download`)
      .set('Authorization', `Bearer ${charlieToken}`);

    expect(authorizedDownload.status).toBe(200);
    expect(authorizedDownload.headers['content-type']).toContain('pdf');

    // Step 3: Alice revokes Charlie\'s access
    const charlieId = grantRes.body.grant.userId;

    const revokeRes = await request(app)
      .post('/api/permissions/revoke')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({
        documentId: aliceDocId,
        userId: charlieId,
        reason: 'Project phase completed.',
      });

    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.revocation.isRevoked).toBe(true);

    // Step 4: INSTANT CHECK - Charlie attempts download on the very next request
    const postRevocationAttempt = await request(app)
      .get(`/api/documents/${aliceDocId}/download`)
      .set('Authorization', `Bearer ${charlieToken}`);

    // Must be rejected immediately!
    expect(postRevocationAttempt.status).toBe(403);
    expect(postRevocationAttempt.body.reason).toContain('Permission was revoked');

    // Verify a READ_DENIED audit entry was created for the post-revocation attempt
    const postRevokeLog = await query(
      "SELECT * FROM audit_logs WHERE action = 'READ_DENIED' AND actor_email = 'charlie@trustvault.local' ORDER BY timestamp DESC LIMIT 1"
    );
    expect(postRevokeLog.rows[0].status).toBe('DENIED');
  });

  test('Zero-Trust Administrator Restriction: Admin CANNOT read confidential document without explicit grant', async () => {
    // Admin has global visibility to audit logs, but CANNOT read private document files
    const res = await request(app)
      .get(`/api/documents/${bobDocId}/download`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Access Denied');
  });

  test('Privilege Escalation Prevention: Viewer cannot grant access or delete documents', async () => {
    // Charlie tries to grant access to another user
    const grantAttempt = await request(app)
      .post('/api/permissions/grant')
      .set('Authorization', `Bearer ${charlieToken}`)
      .send({
        documentId: aliceDocId,
        userEmail: 'bob@trustvault.local',
        accessLevel: 'read',
      });

    expect(grantAttempt.status).toBe(403);

    // Charlie tries to delete Alice\'s document
    const deleteAttempt = await request(app)
      .delete(`/api/documents/${aliceDocId}`)
      .set('Authorization', `Bearer ${charlieToken}`);

    expect(deleteAttempt.status).toBe(403);
  });

  afterAll(async () => {
    try {
      await query('DELETE FROM document_permissions WHERE user_id IN ($1, $2, $3)', [SEED_IDS.alice, SEED_IDS.bob, SEED_IDS.charlie]);
      await query('DELETE FROM documents WHERE owner_id IN ($1, $2, $3)', [SEED_IDS.alice, SEED_IDS.bob, SEED_IDS.charlie]);
      await query('DELETE FROM users WHERE email LIKE $1', ['%trustvault.local']);
    } catch (e) {}
  });
});
