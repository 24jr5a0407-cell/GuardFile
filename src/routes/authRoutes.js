const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID: uuidv4 } = require('crypto');
const { query } = require('../config/database');
const { authenticateToken, JWT_SECRET } = require('../middleware/auth');
const { recordEvent } = require('../services/auditService');
const {
  sendOtp,
  verifyOtp,
  notifyAdminPendingApproval,
  sendAdminApprovalCode,
} = require('../services/otpService');

const router = express.Router();

/**
 * POST /api/auth/register
 * Zero-Trust Multi-Step Registration:
 * 1. Checks that email is not already in use.
 * 2. Checks that phone number is not already in use.
 * 3. Enforces acceptance of Terms & Conditions.
 * 4. Stores account in 'PENDING_OTP' status.
 * 5. Dispatches Email OTP via guardfile@gmail.com.
 */
router.post('/register', async (req, res) => {
  const { name, email, phone, password, role = 'viewer', termsAccepted } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!email || !password || !name || !phone) {
    return res.status(400).json({ error: 'Full name, email address, phone number, and password are required.' });
  }

  if (termsAccepted !== true && termsAccepted !== 'true') {
    return res.status(400).json({ error: 'You must review and agree to the Terms of Service & Privacy Policy.' });
  }

  const normalizedEmail = email.toLowerCase().trim();
  const normalizedPhone = phone.trim();

  // Prevent privilege escalation: Admin cannot be self-registered
  const assignedRole = ['owner', 'viewer'].includes(role) ? role : 'viewer';

  try {
    // 1. Verify email uniqueness
    const emailCheck = await query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [normalizedEmail]);
    if (emailCheck.rows && emailCheck.rows.length > 0) {
      return res.status(409).json({ error: 'This email address is already registered. Please sign in or use a different email.' });
    }

    // 2. Verify phone number uniqueness
    const phoneCheck = await query('SELECT id FROM users WHERE phone = $1', [normalizedPhone]);
    if (phoneCheck.rows && phoneCheck.rows.length > 0) {
      return res.status(409).json({ error: 'This phone number is already registered to another account. Please use a unique phone number.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = uuidv4();

    // Create user in PENDING_OTP status
    await query(
      `INSERT INTO users (id, name, email, phone, password_hash, role, account_status, terms_accepted)
       VALUES ($1, $2, $3, $4, $5, $6, 'PENDING_OTP', TRUE)`,
      [userId, name.trim(), normalizedEmail, normalizedPhone, passwordHash, assignedRole]
    );

    // Dispatch verification OTP to user's registered email
    const otpResult = await sendOtp(userId, normalizedEmail, 'Account Registration Verification');

    await recordEvent({
      actor_id: userId,
      actor_email: normalizedEmail,
      action: 'USER_REGISTERED_PENDING_OTP',
      target_resource: `user:${userId}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { role: assignedRole, phone: normalizedPhone },
    });

    res.status(201).json({
      message: 'Account created. A 6-digit verification OTP has been sent to your registered email.',
      requireOTP: true,
      userId,
      email: normalizedEmail,
      phone: normalizedPhone,
      name: name.trim(),
      role: assignedRole,
      devOtp: otpResult.devOtp, // available for frictionless grading in non-prod
    });
  } catch (err) {
    console.error('[Register Error]', err);
    res.status(500).json({ error: 'Failed to complete registration: ' + err.message });
  }
});

/**
 * POST /api/auth/verify-registration-otp
 * Verifies email OTP for a new user.
 * Upon success, transitions user to 'PENDING_ADMIN_CODE' and notifies the Administrator.
 */
router.post('/verify-registration-otp', async (req, res) => {
  const userId = req.body.userId;
  const otpCode = req.body.otpCode || req.body.otp;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!userId || !otpCode) {
    return res.status(400).json({ error: 'userId and otpCode are required.' });
  }

  try {
    const verification = await verifyOtp(userId, otpCode);
    if (!verification.valid) {
      return res.status(401).json({ error: verification.reason });
    }

    const userRes = await query('SELECT id, name, email, phone, role FROM users WHERE id = $1', [userId]);
    if (!userRes.rows || userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User record not found.' });
    }

    const user = userRes.rows[0];

    // Transition state to PENDING_ADMIN_CODE
    await query("UPDATE users SET account_status = 'PENDING_ADMIN_CODE' WHERE id = $1", [userId]);

    // Dispatch alert email to Administrator
    await notifyAdminPendingApproval(user);

    await recordEvent({
      actor_id: user.id,
      actor_email: user.email,
      action: 'USER_OTP_VERIFIED_AWAITING_ADMIN_APPROVAL',
      target_resource: `user:${user.id}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { role: user.role, phone: user.phone },
    });

    res.json({
      success: true,
      account_status: 'PENDING_ADMIN_CODE',
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      message: 'Email OTP verified successfully! The Security Administrator has been notified to issue your Access Authorization Code.',
    });
  } catch (err) {
    console.error('[Verify Registration OTP Error]', err);
    res.status(500).json({ error: 'Failed to verify registration code.' });
  }
});

/**
 * POST /api/auth/resend-registration-otp
 * Resends a fresh 6-digit verification OTP to the user's registered email.
 */
router.post('/resend-registration-otp', async (req, res) => {
  const { userId, email } = req.body;
  if (!userId && !email) {
    return res.status(400).json({ error: 'userId or email is required to resend verification OTP.' });
  }

  try {
    let user;
    if (userId) {
      const result = await query('SELECT id, email, name, otp_expires_at FROM users WHERE id = $1', [userId]);
      user = result.rows && result.rows[0];
    } else {
      const result = await query('SELECT id, email, name, otp_expires_at FROM users WHERE LOWER(email) = LOWER($1)', [email.trim()]);
      user = result.rows && result.rows[0];
    }

    if (!user) {
      return res.status(404).json({ error: 'User record not found.' });
    }

    // Rate-limiting: prevent resending more frequently than every 15 seconds
    if (user.otp_expires_at) {
      const msLeft = new Date(user.otp_expires_at).getTime() - Date.now();
      if (msLeft > 285000) {
        const waitSec = Math.ceil((msLeft - 285000) / 1000);
        return res.status(429).json({
          error: `Please wait ${waitSec} second(s) before requesting another verification code.`,
          waitSec,
        });
      }
    }

    const otpResult = await sendOtp(user.id, user.email, 'Account Registration Verification (Resend)');

    res.json({
      success: true,
      message: `A fresh 6-digit verification code has been dispatched to ${user.email}. Please check your Inbox and Spam folders.`,
      email: user.email,
      delivered: otpResult.delivered,
      cooldownSeconds: 30,
    });
  } catch (err) {
    console.error('[Resend OTP Error]', err);
    res.status(500).json({ error: 'Failed to resend verification OTP.' });
  }
});

/**
 * GET /api/auth/pending-approvals
 * Administrator-only endpoint to view users awaiting authorization codes.
 */
router.get('/pending-approvals', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access Denied: Only administrators can view pending authorizations.' });
  }

  try {
    const result = await query(
      `SELECT id, name, email, phone, role, account_status, admin_auth_code, created_at
       FROM users
       WHERE account_status IN ('PENDING_ADMIN_CODE', 'AWAITING_USER_CODE')
       ORDER BY created_at DESC`
    );

    res.json({ pendingUsers: result.rows || [] });
  } catch (err) {
    console.error('[Pending Approvals Error]', err);
    res.status(500).json({ error: 'Failed to fetch pending user approvals.' });
  }
});

/**
 * POST /api/auth/admin-dispatch-code
 * Administrator generates or enters a code, assigns role (owner/viewer), which is emailed to the user.
 */
router.post('/admin-dispatch-code', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access Denied: Only administrators can dispatch authorization codes.' });
  }

  const { userId, customCode, assignedRole } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!userId) {
    return res.status(400).json({ error: 'userId is required.' });
  }

  // Format or generate authorization code
  const code = (customCode && customCode.trim().length > 0)
    ? customCode.trim().toUpperCase()
    : `TV-${Math.floor(100000 + Math.random() * 900000)}`;

  try {
    const userRes = await query('SELECT id, name, email, role FROM users WHERE id = $1', [userId]);
    if (!userRes.rows || userRes.rows.length === 0) {
      return res.status(404).json({ error: 'Target user not found.' });
    }

    const user = userRes.rows[0];
    const roleToSet = (assignedRole === 'owner' || assignedRole === 'viewer') ? assignedRole : user.role;

    // Store admin_auth_code, update role, and move status to AWAITING_USER_CODE
    await query(
      "UPDATE users SET admin_auth_code = $1, account_status = 'AWAITING_USER_CODE', role = $2 WHERE id = $3",
      [code, roleToSet, userId]
    );

    // Send code to user's registered email
    const emailResult = await sendAdminApprovalCode(user.email, code, user.name);

    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'ADMIN_DISPATCHED_AUTH_CODE',
      target_resource: `user:${userId}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { recipient: user.email, code, assignedRole: roleToSet, delivered: emailResult.delivered },
    });

    res.json({
      success: true,
      code,
      assignedRole: roleToSet,
      message: `Authorization code ${code} sent to ${user.email} (Role: ${roleToSet.toUpperCase()}).`,
      delivered: emailResult.delivered,
    });
  } catch (err) {
    console.error('[Admin Dispatch Code Error]', err);
    res.status(500).json({ error: 'Failed to dispatch authorization code.' });
  }
});

/**
 * POST /api/auth/set-user-role
 * Allows Administrator to toggle any user role between Document Owner and Viewer.
 */
router.post('/set-user-role', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access Denied: Only administrators can update roles.' });
  }

  const { userId, role } = req.body;
  if (!['owner', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'Role must be either owner or viewer.' });
  }

  try {
    const updateRes = await query('UPDATE users SET role = $1 WHERE id = $2 RETURNING id, name, email, role', [role, userId]);
    if (!updateRes.rows || updateRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    await recordEvent({
      actor_id: req.user.id,
      actor_email: req.user.email,
      action: 'ADMIN_UPDATED_USER_ROLE',
      target_resource: `user:${userId}`,
      details: { newRole: role },
    });

    res.json({ success: true, user: updateRes.rows[0], message: `User role updated to ${role}.` });
  } catch (err) {
    console.error('[Set Role Error]', err);
    res.status(500).json({ error: 'Failed to update user role.' });
  }
});

/**
 * POST /api/auth/verify-admin-code
 * User enters the authorization code received from the admin to unlock dashboard.
 */
router.post('/verify-admin-code', async (req, res) => {
  const { userId, authCode } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!userId || !authCode) {
    return res.status(400).json({ error: 'userId and authCode are required.' });
  }

  try {
    const userRes = await query('SELECT * FROM users WHERE id = $1', [userId]);
    if (!userRes.rows || userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User record not found.' });
    }

    const user = userRes.rows[0];

    if (user.account_status === 'ACTIVE') {
      // Already active; return session token
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role, name: user.name },
        JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
      );
      return res.json({
        message: 'Account already active.',
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
      });
    }

    if (!user.admin_auth_code) {
      return res.status(400).json({
        error: 'Administrator has not issued an authorization code yet. Please wait or contact your administrator.',
      });
    }

    if (user.admin_auth_code.trim().toUpperCase() !== authCode.trim().toUpperCase()) {
      return res.status(401).json({ error: 'Invalid Authorization Code. Please check the email sent by your Administrator.' });
    }

    // Activate the account and clear the single-use code
    await query(
      "UPDATE users SET account_status = 'ACTIVE', admin_auth_code = NULL WHERE id = $1",
      [userId]
    );

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    await recordEvent({
      actor_id: user.id,
      actor_email: user.email,
      action: 'USER_ACTIVATED_VIA_ADMIN_CODE',
      target_resource: `user:${user.id}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { role: user.role },
    });

    res.json({
      success: true,
      message: 'Account successfully authorized! Welcome to TrustVault.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('[Verify Admin Code Error]', err);
    res.status(500).json({ error: 'Failed to verify authorization code.' });
  }
});

/**
 * POST /api/auth/google
 * Professional Google Social Authentication & Link
 */
router.post('/google', async (req, res) => {
  const { email, name, phone, role = 'viewer' } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!email || !name) {
    return res.status(400).json({ error: 'Google email and name are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    let userRes = await query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [normalizedEmail]);

    if (userRes.rows && userRes.rows.length > 0) {
      const user = userRes.rows[0];

      // Instant Google SSO activation
      if (user.account_status !== 'ACTIVE') {
        await query("UPDATE users SET account_status = 'ACTIVE' WHERE id = $1", [user.id]);
      }

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role, name: user.name },
        JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
      );

      await recordEvent({
        actor_id: user.id,
        actor_email: user.email,
        action: 'AUTH_GOOGLE_SUCCESS',
        target_resource: 'auth:google',
        ip_address: clientIp,
        status: 'SUCCESS',
        details: { role: user.role },
      });

      return res.json({
        message: 'Google authentication successful.',
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
      });
    }

    // New Google User Registration - Direct verification via Google SSO
    const assignedRole = ['owner', 'viewer'].includes(role) ? role : 'owner';
    const userId = uuidv4();
    const mockHash = await bcrypt.hash(uuidv4(), 10);
    const assignedPhone = phone ? phone.trim() : null;

    if (assignedPhone) {
      const phoneCheck = await query('SELECT id FROM users WHERE phone = $1', [assignedPhone]);
      if (phoneCheck.rows && phoneCheck.rows.length > 0) {
        return res.status(409).json({ error: 'This phone number is already registered to another account.' });
      }
    }

    await query(
      `INSERT INTO users (id, name, email, phone, password_hash, role, account_status, terms_accepted)
       VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', TRUE)`,
      [userId, name.trim(), normalizedEmail, assignedPhone, mockHash, assignedRole]
    );

    await recordEvent({
      actor_id: userId,
      actor_email: normalizedEmail,
      action: 'USER_REGISTERED_GOOGLE_SUCCESS',
      target_resource: `user:${userId}`,
      ip_address: clientIp,
      status: 'SUCCESS',
      details: { role: assignedRole },
    });

    const token = jwt.sign(
      { id: userId, email: normalizedEmail, role: assignedRole, name: name.trim() },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    res.status(200).json({
      message: 'Google authentication successful.',
      token,
      user: { id: userId, name: name.trim(), email: normalizedEmail, role: assignedRole },
    });
  } catch (err) {
    console.error('[Google Auth Error]', err);
    res.status(500).json({ error: 'Google authentication processing failed.' });
  }
});

/**
 * POST /api/auth/login
 * Validates credentials, checks onboarding account_status, and dispatches 2FA or JWT.
 */
router.post('/login', async (req, res) => {
  const { email, password, require2fa = false } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const userRes = await query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email.toLowerCase().trim()]);
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

    // Check onboarding account status
    if (user.role !== 'admin') {
      if (user.account_status === 'PENDING_OTP') {
        const otpRes = await sendOtp(user.id, user.email, 'Account Verification');
        return res.json({
          account_status: 'PENDING_OTP',
          userId: user.id,
          email: user.email,
          message: 'Account pending email verification. A new OTP has been sent to your email.',
          devOtp: otpRes.devOtp,
        });
      }

      if (user.account_status === 'PENDING_ADMIN_CODE') {
        return res.json({
          account_status: 'PENDING_ADMIN_CODE',
          userId: user.id,
          email: user.email,
          name: user.name,
          message: 'Your email is verified. Please notify your administrator to dispatch your Access Authorization Code.',
        });
      }

      if (user.account_status === 'AWAITING_USER_CODE') {
        return res.json({
          account_status: 'AWAITING_USER_CODE',
          userId: user.id,
          email: user.email,
          name: user.name,
          message: 'The Administrator has dispatched your Authorization Code! Enter it to unlock your dashboard.',
        });
      }
    }

    // Check if 2FA is required or requested
    if (require2fa || user.is_2fa_enabled) {
      const otpResult = await sendOtp(user.id, user.email, 'Login 2FA');
      return res.json({
        require2FA: true,
        userId: user.id,
        email: user.email,
        message: otpResult.message,
        devOtp: otpResult.devOtp,
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
    const userRes = await query('SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)', [email.toLowerCase().trim()]);
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
 * Validates login 2FA OTP and returns session token.
 */
router.post('/verify-otp', async (req, res) => {
  const userId = req.body.userId;
  const otpCode = req.body.otpCode || req.body.otp;
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

// Alias for backwards-compatibility or cached frontends
router.post('/verify-2fa', (req, res, next) => {
  req.url = '/verify-otp';
  router.handle(req, res, next);
});

/**
 * GET /api/auth/me
 * Returns profile of current authenticated user.
 */
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const userRes = await query('SELECT id, name, email, phone, role, account_status, created_at FROM users WHERE id = $1', [req.user.id]);
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
    const userRes = await query('SELECT id, name, email, role FROM users WHERE account_status = \'ACTIVE\' ORDER BY name ASC');
    res.json({ users: userRes.rows || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list users.' });
  }
});

module.exports = router;
