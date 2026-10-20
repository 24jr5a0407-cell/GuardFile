/**
 * Role-Based Access Control (RBAC) Middleware
 * Restricts endpoint invocation to specified system roles (admin, owner, viewer).
 */

function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized: Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden: Insufficient Privileges',
        message: `Your account role (${req.user.role}) is not authorized to perform this operation. Required: ${allowedRoles.join(', ')}`,
      });
    }

    next();
  };
}

const requireAdmin = requireRole(['admin']);
const requireOwner = requireRole(['owner', 'admin']); // Admin has administrative management rights where specified

module.exports = {
  requireRole,
  requireAdmin,
  requireOwner,
};
