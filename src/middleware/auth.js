const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'trustvault_super_secret_cryptographic_jwt_key_2026_safe';

/**
 * Verifies JWT and injects authenticated user context into req.user
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : (req.query.token || req.cookies?.token);

  if (!token) {
    return res.status(401).json({
      error: 'Authentication Required',
      message: 'Missing or malformed Authorization header. Bearer token required.',
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      name: decoded.name,
    };
    next();
  } catch (err) {
    return res.status(401).json({
      error: 'Invalid Token',
      message: err.name === 'TokenExpiredError' ? 'Authentication token has expired. Please log in again.' : 'Invalid token signature.',
    });
  }
}

/**
 * Optional authentication middleware for logging requests that may be unauthenticated
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
    } catch {
      // Ignored for optional
    }
  }
  next();
}

module.exports = {
  authenticateToken,
  optionalAuth,
  JWT_SECRET,
};
