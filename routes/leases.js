const express = require('express');
const { body, validationResult } = require('express-validator');
const { query, getClient } = require('../config/db');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');

const router = express.Router();
router.use(authenticate);

// GET /leases/mine — tenant sees their own lease
router.get('/mine', requireRole('tenant'), async (req, res) => {
  try {
    const result = await query(`
      SELECT l.*,
        u.unit_number, u.bedrooms, u.bathrooms,
        p.name AS property_name, p.address, p.city, p.image_url,
        ll.full_name AS landlord_name, ll.email AS landlord_email, ll.phone AS landlord_phone
      FROM leases l
      JOIN units u ON u.id = l.unit_id
      JOIN properties p ON p.id = u.property_id
      JOIN users ll ON ll.id = l.landlord_id
      WHERE l.tenant_id = $1 AND l.is_active = TRUE`, [req.user.id]);

    res.json(result.rows);
  } catch {
    res.status(500).json({ error: 'Failed to fetch lease' });
  }
});

// GET /leases — landlord sees all leases
router.get('/', requireRole('landlord'), async (req, res) => {
  try {
    const result = await query(`
      SELECT l.*,
        u.unit_number, p.name AS property_name,
        t.full_name AS tenant_name, t.email AS tenant_email, t.phone AS tenant_phone
      FROM leases l
      JOIN units u ON u.id = l.unit_id
      JOIN properties p ON p.id = u.property_id
      JOIN users t ON t.id = l.tenant_id
      WHERE l.landlord_id = $1
      ORDER BY l.created_at DESC`, [req.user.id]);

    res.json(result.rows);
  } catch {
    res.status(500).json({ error: 'Failed to fetch leases' });
  }
});

// POST /leases — landlord assigns tenant to unit
router.post('/', requireRole('landlord'), [
  body('unit_id').isUUID(),
  body('tenant_email').isEmail().normalizeEmail(),
  body('start_date').isISO8601(),
  body('end_date').optional().isISO8601(),
  body('rent_amount').isFloat({ min: 0 }),
  body('due_day').isInt({ min: 1, max: 28 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const client = await getClient();
  try {
    await client.query('BEGIN');

    const { unit_id, tenant_email, start_date, end_date, rent_amount, due_day } = req.body;

    // Verify unit belongs to this landlord and is vacant
    const unitRes = await client.query(
      'SELECT u.id, u.is_occupied FROM units u JOIN properties p ON p.id=u.property_id WHERE u.id=$1 AND p.landlord_id=$2',
      [unit_id, req.user.id]
    );
    if (!unitRes.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Unit not found' }); }
    if (unitRes.rows[0].is_occupied) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Unit is already occupied' }); }

    // Find tenant
    const tenantRes = await client.query("SELECT id FROM users WHERE email=$1 AND role='tenant'", [tenant_email]);
    if (!tenantRes.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Tenant not found — they must register first' }); }

    const tenantId = tenantRes.rows[0].id;

    // Ensure tenant has no other active lease
    const existingLease = await client.query('SELECT id FROM leases WHERE tenant_id=$1 AND is_active=TRUE', [tenantId]);
    if (existingLease.rows[0]) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Tenant already has an active lease' }); }

    // Create lease + mark unit occupied (atomic)
    const leaseRes = await client.query(
      'INSERT INTO leases (unit_id,tenant_id,landlord_id,start_date,end_date,rent_amount,due_day) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [unit_id, tenantId, req.user.id, start_date, end_date || null, rent_amount, due_day]
    );
    await client.query('UPDATE units SET is_occupied=TRUE, updated_at=CURRENT_TIMESTAMP WHERE id=$1', [unit_id]);
    await client.query('COMMIT');

    await auditLog(req.user.id, 'LEASE_CREATED', 'leases', leaseRes.rows[0].id, { unit_id, tenant_email, rent_amount }, req.ip);
    res.status(201).json(leaseRes.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Failed to create lease' });
  } finally {
    client.release();
  }
});

// PUT /leases/:id/terminate — end lease, free unit
router.put('/:id/terminate', requireRole('landlord'), async (req, res) => {
  const client = await getClient();
  try {
    await client.query('BEGIN');

    const leaseRes = await client.query(
      'SELECT l.*, u.id AS unit_id FROM leases l JOIN units u ON u.id=l.unit_id WHERE l.id=$1 AND l.landlord_id=$2 AND l.is_active=TRUE',
      [req.params.id, req.user.id]
    );
    if (!leaseRes.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Active lease not found' }); }

    const lease = leaseRes.rows[0];
    await client.query('UPDATE leases SET is_active=FALSE, end_date=CURRENT_DATE, updated_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
    await client.query('UPDATE units SET is_occupied=FALSE, updated_at=CURRENT_TIMESTAMP WHERE id=$1', [lease.unit_id]);
    await client.query('COMMIT');

    await auditLog(req.user.id, 'LEASE_TERMINATED', 'leases', req.params.id, {}, req.ip);
    res.json({ message: 'Lease terminated' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to terminate lease' });
  } finally {
    client.release();
  }
});

module.exports = router;
