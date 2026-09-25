const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const { query } = require('../config/db');
const { auditLog } = require('../middleware/auth');

const router = express.Router();

const BCRYPT_ROUNDS = 12;

const generateTokens = (userId, role) => {
  const accessToken = jwt.sign(
    { userId, role },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    { userId, jti: uuidv4() },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
  return { accessToken, refreshToken };
};

const storeRefreshToken = async (userId, token) => {
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await query(
    'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
    [userId, token, expires]
  );
};

// POST /auth/register
router.post('/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[A-Za-z])(?=.*\d)/),
  body('full_name').trim().notEmpty().isLength({ max: 255 }),
  body('role').isIn(['landlord', 'tenant']),
  body('phone').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { email, password, full_name, role, phone } = req.body;

    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = await query(
      'INSERT INTO users (email, password_hash, full_name, role, phone) VALUES ($1,$2,$3,$4,$5) RETURNING id, email, full_name, role',
      [email, password_hash, full_name, role, phone || null]
    );

    const user = result.rows[0];
    const { accessToken, refreshToken } = generateTokens(user.id, user.role);
    await storeRefreshToken(user.id, refreshToken);
    await auditLog(user.id, 'USER_REGISTERED', 'users', user.id, { role }, req.ip);

    res.status(201).json({ user, accessToken, refreshToken });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /auth/login
router.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { email, password } = req.body;

    const result = await query(
      'SELECT id, email, password_hash, full_name, role, is_active FROM users WHERE email = $1',
      [email]
    );
    const user = result.rows[0];

    // Run bcrypt either way to prevent timing attacks
    const DUMMY_HASH = '$2b$12$invalidhashtopreventtimingattackXXXXXXXXXXXXXXXXXXXXXX';
    const match = await bcrypt.compare(password, user?.password_hash || DUMMY_HASH);

    if (!user || !match) {
      await auditLog(null, 'LOGIN_FAILED', 'users', null, { email }, req.ip);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });

    const { accessToken, refreshToken } = generateTokens(user.id, user.role);
    await storeRefreshToken(user.id, refreshToken);
    await auditLog(user.id, 'LOGIN_SUCCESS', 'users', user.id, {}, req.ip);

    const { password_hash, ...safeUser } = user;
    res.json({ user: safeUser, accessToken, refreshToken });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /auth/refresh
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const stored = await query(
      'SELECT * FROM refresh_tokens WHERE token = $1 AND user_id = $2 AND expires_at > NOW()',
      [refreshToken, decoded.userId]
    );
    if (!stored.rows[0]) return res.status(401).json({ error: 'Invalid or expired refresh token' });

    // Rotate: delete old, issue new
    await query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);

    const userResult = await query('SELECT id, role FROM users WHERE id = $1', [decoded.userId]);
    const user = userResult.rows[0];
    const tokens = generateTokens(user.id, user.role);
    await storeRefreshToken(user.id, tokens.refreshToken);

    res.json(tokens);
  } catch {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// POST /auth/logout
router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) await query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    res.json({ message: 'Logged out' });
  } catch {
    res.status(500).json({ error: 'Logout failed' });
  }
});

module.exports = router;
