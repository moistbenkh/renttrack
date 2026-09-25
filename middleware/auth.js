const jwt = require('jsonwebtoken');
const { query } = require('../config/db');

// Verify JWT and attach user to request
const authenticate = async (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const result = await query(
      'SELECT id, email, role, full_name, is_active FROM users WHERE id = $1',
      [decoded.userId]
    );

    const user = result.rows[0];
    if (!user || !user.is_active) {
      return res.status(401).json({ error: 'Account not found or inactive' });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Role-based access control
const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};

// Append-only audit trail
const auditLog = async (userId, action, tableName, recordId, details, ip) => {
  try {
    await query(
      'INSERT INTO audit_log (user_id, action, table_name, record_id, details, ip_address) VALUES ($1,$2,$3,$4,$5,$6)',
      [userId, action, tableName, recordId, JSON.stringify(details ?? {}), ip]
    );
  } catch (err) {
    // Audit failures should never crash the app — just log
    console.error('Audit log write failed:', err.message);
  }
};

module.exports = { authenticate, requireRole, auditLog };
