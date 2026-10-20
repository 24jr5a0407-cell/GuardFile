const request = require('supertest');
const { app } = require('../server');
const { migrate } = require('../src/db/migrate');
const { seed } = require('../src/db/seed');
const { resolveSecurePath } = require('../src/services/storageService');

let ownerToken;

beforeAll(async () => {
  process.env.NODE_ENV = 'test';
  await migrate();
  await seed();

  const res = await request(app)
    .post('/api/auth/login')
    .send({ email: 'alice@trustvault.local', password: 'OwnerPassword123!' });
  ownerToken = res.body.token;
});

describe('File Upload Security, MIME Verification & Path Traversal Defense', () => {

  test('Rejects MIME Spoofing: Executable binary disguised with .pdf extension', async () => {
    // Windows PE executable header: 'MZ' (0x4D, 0x5A)
    const maliciousExeBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00]);

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Disguised Malware Document')
      .field('category', 'Legal')
      .attach('file', maliciousExeBuffer, {
        filename: 'invoice_march_2026.pdf',
        contentType: 'application/pdf',
      });

    expect(res.status).toBe(400);
    expect(res.body.reason).toContain('matches dangerous executable signature');
  });

  test('Rejects Path Traversal in filename sequence', async () => {
    const validPdfBuffer = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (Safe Doc) >>\nendobj\n%%EOF');

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Path Traversal Attack File')
      .attach('file', validPdfBuffer, {
        filename: '..traversal_test.pdf',
        contentType: 'application/pdf',
      });

    expect(res.status).toBe(400);
    expect(res.body.message).toContain('Path traversal');
  });

  test('Storage Isolation Engine: resolveSecurePath blocks escaping secure directory', () => {
    expect(() => resolveSecurePath('../../etc/passwd')).toThrow('Path Traversal');
    expect(() => resolveSecurePath('..\\..\\windows\\system32\\cmd.exe')).toThrow('Path Traversal');
    expect(() => resolveSecurePath('/etc/shadow')).toThrow('Path Traversal');
  });

  test('Accepts legitimate PDF with genuine magic bytes', async () => {
    const genuinePdf = Buffer.from('%PDF-1.7\n1 0 obj\n<< /Title (Genuine Contract) >>\nendobj\n%%EOF');

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Genuine Executed NDA')
      .field('category', 'Legal')
      .attach('file', genuinePdf, {
        filename: 'executed_nda_final.pdf',
        contentType: 'application/pdf',
      });

    expect(res.status).toBe(201);
    expect(res.body.document).toBeDefined();
    expect(res.body.document.fileHash).toHaveLength(64);
  });
});
