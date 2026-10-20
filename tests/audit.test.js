const { query } = require('../src/config/database');
const { verifyChain, recordEvent } = require('../src/services/auditService');
const { migrate } = require('../src/db/migrate');

beforeAll(async () => {
  process.env.NODE_ENV = 'test';
  await migrate();
});

describe('Tamper-Evident Immutable Audit Trail Ledger', () => {

  test('Database Trigger blocks direct UPDATE on audit_logs table', async () => {
    // Record an initial event
    const recorded = await recordEvent({
      action: 'TEST_EVENT',
      target_resource: 'system:test',
      ip_address: '127.0.0.1',
      status: 'SUCCESS',
      details: { test: true },
    });

    // Attempt direct SQL UPDATE on the ledger
    let threwError = false;
    try {
      await query(
        "UPDATE audit_logs SET status = 'DENIED' WHERE id = $1",
        [recorded.id]
      );
    } catch (err) {
      threwError = true;
      expect(err.message).toContain('SECURITY VIOLATION');
    }

    expect(threwError).toBe(true);
  });

  test('Database Trigger blocks direct DELETE on audit_logs table', async () => {
    const recorded = await recordEvent({
      action: 'TEST_DELETE_EVENT',
      target_resource: 'system:delete_test',
      ip_address: '127.0.0.1',
      status: 'SUCCESS',
    });

    let threwError = false;
    try {
      await query('DELETE FROM audit_logs WHERE id = $1', [recorded.id]);
    } catch (err) {
      threwError = true;
      expect(err.message).toContain('SECURITY VIOLATION');
    }

    expect(threwError).toBe(true);
  });

  test('Cryptographic Verification confirms 100% unbroken chain integrity', async () => {
    const result = await verifyChain();
    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBeGreaterThan(0);
    expect(result.headHash).toBeDefined();
  });
});
