const request = require('supertest');
const { app } = require('../server');
const { query } = require('../src/config/database');
const { migrate } = require('../src/db/migrate');
const { seed } = require('../src/db/seed');

let adminToken;
const uniqueId = Date.now();
const testUser = {
  name: 'Sarah Connor',
  email: `sarah.connor.${uniqueId}@cyberdyne.org`,
  phone: `+141555${Math.floor(100000 + Math.random() * 900000)}`,
  password: 'SecurePass2026!#',
  role: 'owner',
  termsAccepted: true,
};

beforeAll(async () => {
  process.env.NODE_ENV = 'test';
  await migrate();
  await seed();

  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'AdminPassword123!' });
  adminToken = loginRes.body.token;
});

describe('Zero-Trust Registration & Admin Authorization Flow', () => {
  test('1. Registration fails if terms & conditions are not accepted', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ ...testUser, termsAccepted: false });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Terms of Service/i);
  });

  test('2. Successful registration creates user in PENDING_OTP status and dispatches OTP', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send(testUser);

    expect(res.status).toBe(201);
    expect(res.body.requireOTP).toBe(true);
    expect(res.body.email).toBe(testUser.email.toLowerCase());
    expect(res.body.userId).toBeDefined();
  });

  test('3. Prevents duplicate email registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        ...testUser,
        phone: '+14155559999', // Different phone, duplicate email
      });

    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/email address is already registered/i);
  });

  test('4. Prevents duplicate phone number registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        ...testUser,
        email: `different.email.${uniqueId}@cyberdyne.org`, // Different email, duplicate phone
      });

    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/phone number is already registered/i);
  });

  test('5. User enters email OTP and advances to PENDING_ADMIN_CODE', async () => {
    const userRow = (await query('SELECT id, otp_code FROM users WHERE email = $1', [testUser.email.toLowerCase()])).rows[0];
    expect(userRow.otp_code).toBeDefined();

    const verifyRes = await request(app)
      .post('/api/auth/verify-registration-otp')
      .send({
        userId: userRow.id,
        otpCode: userRow.otp_code,
      });

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.account_status).toBe('PENDING_ADMIN_CODE');
  });

  test('6. Non-admin cannot access pending user approvals (Zero-Trust Enforcement)', async () => {
    const viewerLogin = await request(app)
      .post('/api/auth/login')
      .send({ email: 'charlie@trustvault.local', password: 'ViewerPassword123!' });

    const forbiddenRes = await request(app)
      .get('/api/auth/pending-approvals')
      .set('Authorization', `Bearer ${viewerLogin.body.token}`);

    expect(forbiddenRes.status).toBe(403);
  });

  test('7. Admin can view pending users and dispatch Authorization Code', async () => {
    const pendingListRes = await request(app)
      .get('/api/auth/pending-approvals')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(pendingListRes.status).toBe(200);
    const target = pendingListRes.body.pendingUsers.find(u => u.email === testUser.email.toLowerCase());
    expect(target).toBeDefined();

    const dispatchRes = await request(app)
      .post('/api/auth/admin-dispatch-code')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        userId: target.id,
        customCode: 'AUTH-TEST-777',
      });

    expect(dispatchRes.status).toBe(200);
    expect(dispatchRes.body.code).toBe('AUTH-TEST-777');
  });

  test('8. User enters incorrect admin code -> rejected with 401', async () => {
    const userRow = (await query('SELECT id FROM users WHERE email = $1', [testUser.email.toLowerCase()])).rows[0];

    const rejectRes = await request(app)
      .post('/api/auth/verify-admin-code')
      .send({
        userId: userRow.id,
        authCode: 'WRONG-CODE-999',
      });

    expect(rejectRes.status).toBe(401);
  });

  test('9. User enters valid admin code -> Activated, receives JWT token', async () => {
    const userRow = (await query('SELECT id FROM users WHERE email = $1', [testUser.email.toLowerCase()])).rows[0];

    const activateRes = await request(app)
      .post('/api/auth/verify-admin-code')
      .send({
        userId: userRow.id,
        authCode: 'AUTH-TEST-777',
      });

    expect(activateRes.status).toBe(200);
    expect(activateRes.body.token).toBeDefined();
    expect(activateRes.body.user.role).toBe('owner');

    // Verify account is now ACTIVE in database
    const updated = (await query('SELECT account_status FROM users WHERE id = $1', [userRow.id])).rows[0];
    expect(updated.account_status).toBe('ACTIVE');
  });
});
