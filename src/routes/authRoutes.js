const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID: uuidv4 } = require('crypto');
const { query } = require('../config/database');
const { authenticateToken, JWT_SECRET } = require('../middleware/auth');
const { recordEvent } = require('../services/auditService');
const { sendOtp, verifyOtp } = require('../services/otpService');

const router = express.Router();

/**
 * POST /api/auth/register
 * Self-registration defaults to role='viewer' for security.
 */
router.post('/register', async (req, res) => {
  const { name, email, password, role = 'viewer' } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  // Prevent privilege escalation via registration
  const assignedRole = ['owner', 'viewer'].includes(role) ? role : 'viewer';

  try {
    const existing = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (existing.rows && existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = uuidv4();

    await query(
      'INSERT INTO users (id, name, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)',
      [userId, name.trim(), email.toLowerCase().trim(), passwordHash, assignedRole]
    );

    await recordEvent({
      actor_id: userId,
      actor_email: email,
      action: 'USER_REGISTERED',
      target_resource: `user:${userId}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { role: assignedRole },
    });

    res.status(201).json({
      message: 'Account created successfully.',
      user: { id: userId, name, email, role: assignedRole },
    });
  } catch (err) {
    console.error('[Register Error]', err);
    res.status(500).json({ error: 'Failed to create user account.' });
  }
});

/**
 * POST /api/auth/login
 * Validates credentials and dispatches OTP or returns session JWT.
 */
router.post('/login', async (req, res) => {
  const { email, password, require2fa = false } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const userRes = await query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    const user = userRes.rows && userRes.rows[0];

    if (!user) {
      await recordEvent({
        actor_id: null,
        actor_email: email,
        action: 'AUTH_LOGIN_FAILED',
        target_resource: 'auth:login',
        ip_address: clientIp,
        status: 'DENIED',
        details: { reason: 'User not found.' },
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      await recordEvent({
        actor_id: user.id,
        actor_email: user.email,
        action: 'AUTH_LOGIN_FAILED',
        target_resource: 'auth:login',
        ip_address: clientIp,
        status: 'DENIED',
        details: { reason: 'Incorrect password.' },
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Check if 2FA is required or requested
    if (require2fa || user.is_2fa_enabled) {
      const otpResult = await sendOtp(user.id, user.email, 'Login 2FA');
      return res.json({
        require2FA: true,
        userId: user.id,
        email: user.email,
        message: otpResult.message,
        devOtp: otpResult.devOtp, // Provided in non-prod for smooth test automation
      });
    }

    // Direct JWT session generation
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    await recordEvent({
      actor_id: user.id,
      actor_email: user.email,
      action: 'AUTH_LOGIN_SUCCESS',
      target_resource: 'auth:login',
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { role: user.role },
    });

    res.json({
      message: 'Authentication successful.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('[Login Error]', err);
    res.status(500).json({ error: 'Authentication processing failed.' });
  }
});

/**
 * POST /api/auth/request-otp
 * Explicitly triggers an OTP delivery to user's registered email
 */
router.post('/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });

  try {
    const userRes = await query('SELECT id, email FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (!userRes.rows || userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userRes.rows[0];
    const otpRes = await sendOtp(user.id, user.email, 'Security Verification');
    res.json(otpRes);
  } catch (err) {
    console.error('[Request OTP Error]', err);
    res.status(500).json({ error: 'Failed to dispatch OTP.' });
  }
});

/**
 * POST /api/auth/verify-otp
 * Validates OTP and returns session token.
 */
router.post('/verify-otp', async (req, res) => {
  const { userId, otpCode } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!userId || !otpCode) {
    return res.status(400).json({ error: 'userId and otpCode are required.' });
  }

  try {
    const verification = await verifyOtp(userId, otpCode);
    if (!verification.valid) {
      return res.status(401).json({ error: verification.reason });
    }

    const userRes = await query('SELECT id, name, email, role FROM users WHERE id = $1', [userId]);
    const user = userRes.rows[0];

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    await recordEvent({
      actor_id: user.id,
      actor_email: user.email,
      action: 'AUTH_2FA_SUCCESS',
      target_resource: 'auth:otp',
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { role: user.role },
    });

    res.json({
      message: '2FA verification successful.',
      token,
      user,
    });
  } catch (err) {
    console.error('[Verify OTP Error]', err);
    res.status(500).json({ error: 'Failed to verify OTP.' });
  }
});

/**
 * GET /api/auth/me
 * Returns profile of current authenticated user.
 */
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const userRes = await query('SELECT id, name, email, role, created_at FROM users WHERE id = $1', [req.user.id]);
    if (!userRes.rows || userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json({ user: userRes.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user profile.' });
  }
});

/**
 * GET /api/auth/users
 * Returns list of users for document sharing recipient picker.
 */
router.get('/users', authenticateToken, async (req, res) => {
  try {
    const userRes = await query('SELECT id, name, email, role FROM users ORDER BY name ASC');
    res.json({ users: userRes.rows || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list users.' });
  }
});

module.exports = router;
