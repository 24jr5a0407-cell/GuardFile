const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const { migrate } = require('./src/db/migrate');
const { seed } = require('./src/db/seed');
const { query } = require('./src/config/database');

const authRoutes = require('./src/routes/authRoutes');
const documentRoutes = require('./src/routes/documentRoutes');
const permissionRoutes = require('./src/routes/permissionRoutes');
const auditRoutes = require('./src/routes/auditRoutes');

const app = express();
const PORT = process.env.PORT || 4000;

// Security Headers via Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        objectSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Anti-abuse rate limiting
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '300', 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Rate limit exceeded for this IP.' },
});
app.use('/api/', apiLimiter);

// Specific stricter brute-force rate limit for login
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many authentication attempts. Please wait 15 minutes.' },
});
app.use('/api/auth/login', authLimiter);

// API Endpoints
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/permissions', permissionRoutes);
app.use('/api/audit', auditRoutes);

// Health check endpoints
app.get(['/api/health', '/healthz'], (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'TrustVault Zero-Trust Platform',
    timestamp: new Date().toISOString(),
  });
});

// Serve frontend static files
// IMPORTANT ZERO-TRUST ARCHITECTURE NOTE:
// ONLY public/ is statically served. The /secure_storage directory is strictly OUTSIDE
// the web root and can NEVER be accessed directly by HTTP path traversal!
app.use(express.static(path.join(__dirname, 'public')));

// SPA fallback for non-API routes
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found.' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Centralized error handling
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({
      error: 'File Size Exceeded',
      message: `The uploaded file exceeds the maximum allowed limit of ${process.env.MAX_FILE_SIZE_MB || 15}MB.`,
    });
  }

  if (err.message && (err.message.includes('Forbidden file extension') || err.message.includes('Path traversal'))) {
    return res.status(400).json({
      error: 'File Validation Rejected',
      message: err.message,
    });
  }

  console.error('[Unhandled Server Error]', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred.' : err.message,
  });
});

/**
 * Boots the server and ensures database tables are initialized.
 */
async function startServer() {
  try {
    // 1. Run migrations
    await migrate();

    // 2. Check if database needs seeding
    const usersRes = await query('SELECT count(*) as count FROM users');
    const userCount = parseInt(usersRes.rows[0]?.count || 0, 10);
    if (userCount === 0) {
      console.log('[Init] No users found. Auto-seeding initial environment...');
      await seed();
    }

    if (process.env.NODE_ENV !== 'test') {
      const server = app.listen(PORT, () => {
        console.log(`\n======================================================`);
        console.log(`🛡️  TrustVault Security Engine running at http://localhost:${PORT}`);
        console.log(`🔒 Zero-Trust Object Authorization: ACTIVE`);
        console.log(`📜 Immutable Chained Audit Ledger: ACTIVE`);
        console.log(`======================================================\n`);
      });
      return server;
    }
  } catch (err) {
    console.error('[Startup Failure]', err);
    process.exit(1);
  }
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}

module.exports = { app, startServer };
