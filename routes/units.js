const express = require('express');
const { body, validationResult } = require('express-validator');
const { query, getClient } = require('../config/db');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');

const router = express.Router();
router.use(authenticate);

// GET /units/property/:propertyId — all units with tenant info
router.get('/property/:propertyId', async (req, res) => {
  try {
    if (req.user.role === 'landlord') {
      const check = await query('SELECT id FROM properties WHERE id=$1 AND landlord_id=$2', [req.params.propertyId, req.user.id]);
      if (!check.rows[0]) return res.status(403).json({ error: 'Access denied' });
    }

    const result = await query(`
      SELECT u.*,
        t.full_name   AS tenant_name,
        t.email       AS tenant_email,
        t.phone       AS tenant_phone,
        t.avatar_url  AS tenant_avatar,
        l.id          AS lease_id,
        l.start_date,
        l.due_day,
        l.is_active   AS lease_active
      FROM units u
      LEFT JOIN leases l ON l.unit_id = u.id AND l.is_active = TRUE
      LEFT JOIN users  t ON t.id = l.tenant_id
      WHERE u.property_id = $1
      ORDER BY u.unit_number`, [req.params.propertyId]);

    res.json(result.rows);
  } catch {
    res.status(500).json({ error: 'Failed to fetch units' });
  }
});

// POST /units — create unit
router.post('/', requireRole('landlord'), [
  body('property_id').isUUID(),
  body('unit_number').trim().notEmpty(),
  body('rent_amount').isFloat({ min: 0 }),
  body('bedrooms').optional().isInt({ min: 0 }),
  body('bathrooms').optional().isInt({ min: 0 }),
  body('description').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { property_id, unit_number, rent_amount, bedrooms, bathrooms, description } = req.body;

    const propCheck = await query('SELECT id FROM properties WHERE id=$1 AND landlord_id=$2', [property_id, req.user.id]);
    if (!propCheck.rows[0]) return res.status(403).json({ error: 'Property not found or access denied' });

    const result = await query(
      'INSERT INTO units (property_id,unit_number,rent_amount,bedrooms,bathrooms,description) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [property_id, unit_number, rent_amount, bedrooms ?? 1, bathrooms ?? 1, description || null]
    );

    await auditLog(req.user.id, 'UNIT_CREATED', 'units', result.rows[0].id, { property_id, unit_number, rent_amount }, req.ip);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Unit number already exists in this property' });
    res.status(500).json({ error: 'Failed to create unit' });
  }
});

// PUT /units/:id
router.put('/:id', requireRole('landlord'), async (req, res) => {
  try {
    const check = await query(
      'SELECT u.id FROM units u JOIN properties p ON p.id=u.property_id WHERE u.id=$1 AND p.landlord_id=$2',
      [req.params.id, req.user.id]
    );
    if (!check.rows[0]) return res.status(404).json({ error: 'Unit not found' });

    const { unit_number, rent_amount, bedrooms, bathrooms, description } = req.body;
    const result = await query(
      `UPDATE units SET
        unit_number = COALESCE($1, unit_number),
        rent_amount = COALESCE($2, rent_amount),
        bedrooms    = COALESCE($3, bedrooms),
        bathrooms   = COALESCE($4, bathrooms),
        description = COALESCE($5, description),
        updated_at  = CURRENT_TIMESTAMP
       WHERE id = $6 RETURNING *`,
      [unit_number, rent_amount, bedrooms, bathrooms, description, req.params.id]
    );
    await auditLog(req.user.id, 'UNIT_UPDATED', 'units', req.params.id, req.body, req.ip);
    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: 'Failed to update unit' });
  }
});

// DELETE /units/:id
router.delete('/:id', requireRole('landlord'), async (req, res) => {
  try {
    const check = await query(
      'SELECT u.id FROM units u JOIN properties p ON p.id=u.property_id WHERE u.id=$1 AND p.landlord_id=$2',
      [req.params.id, req.user.id]
    );
    if (!check.rows[0]) return res.status(404).json({ error: 'Unit not found' });

    const occupied = await query('SELECT id FROM leases WHERE unit_id=$1 AND is_active=TRUE', [req.params.id]);
    if (occupied.rows[0]) return res.status(409).json({ error: 'Cannot delete a unit with an active lease' });

    await query('DELETE FROM units WHERE id=$1', [req.params.id]);
    await auditLog(req.user.id, 'UNIT_DELETED', 'units', req.params.id, {}, req.ip);
    res.json({ message: 'Unit deleted' });
  } catch {
    res.status(500).json({ error: 'Failed to delete unit' });
  }
});

module.exports = router;
