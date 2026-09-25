const express = require('express');
const { body, validationResult } = require('express-validator');
const { query, getClient } = require('../config/db');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');

const router = express.Router();
router.use(authenticate);

// GET /properties/stats — dashboard summary for landlord
router.get('/stats', requireRole('landlord'), async (req, res) => {
  try {
    const lid = req.user.id;

    const [unitStats, incomeStats, newLeases] = await Promise.all([
      query(`
        SELECT
          COUNT(u.id)                                        AS total_units,
          COUNT(CASE WHEN u.is_occupied THEN 1 END)         AS occupied_units
        FROM units u
        JOIN properties p ON p.id = u.property_id
        WHERE p.landlord_id = $1`, [lid]),

      query(`
        SELECT COALESCE(SUM(l.rent_amount), 0) AS monthly_income
        FROM leases l WHERE l.landlord_id = $1 AND l.is_active = TRUE`, [lid]),

      query(`
        SELECT COUNT(*) AS new_leases
        FROM leases l WHERE l.landlord_id = $1
          AND l.created_at >= DATE_TRUNC('month', CURRENT_DATE)`, [lid]),
    ]);

    const total    = parseInt(unitStats.rows[0].total_units   || 0);
    const occupied = parseInt(unitStats.rows[0].occupied_units || 0);
    const income   = parseFloat(incomeStats.rows[0].monthly_income || 0);
    const leases   = parseInt(newLeases.rows[0].new_leases || 0);
    const pct      = total > 0 ? Math.round((occupied / total) * 100) : 0;

    res.json({ occupancy_pct: pct, total_units: total, occupied_units: occupied, monthly_income: income, new_leases: leases });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// GET /properties
router.get('/', async (req, res) => {
  try {
    let result;
    if (req.user.role === 'landlord') {
      result = await query(`
        SELECT p.*,
          COUNT(u.id)::int                                 AS total_units,
          COUNT(CASE WHEN u.is_occupied THEN 1 END)::int  AS occupied_units
        FROM properties p
        LEFT JOIN units u ON u.property_id = p.id
        WHERE p.landlord_id = $1
        GROUP BY p.id ORDER BY p.created_at DESC`, [req.user.id]);
    } else {
      result = await query(`
        SELECT p.*, u.unit_number, l.rent_amount, l.due_day
        FROM properties p
        JOIN units u ON u.property_id = p.id
        JOIN leases l ON l.unit_id = u.id
        WHERE l.tenant_id = $1 AND l.is_active = TRUE`, [req.user.id]);
    }
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch properties' });
  }
});

// GET /properties/:id
router.get('/:id', async (req, res) => {
  try {
    const result = await query(`
      SELECT p.*,
        COUNT(u.id)::int                                AS total_units,
        COUNT(CASE WHEN u.is_occupied THEN 1 END)::int AS occupied_units
      FROM properties p
      LEFT JOIN units u ON u.property_id = p.id
      WHERE p.id = $1
      GROUP BY p.id`, [req.params.id]);

    const prop = result.rows[0];
    if (!prop) return res.status(404).json({ error: 'Property not found' });
    if (req.user.role === 'landlord' && prop.landlord_id !== req.user.id)
      return res.status(403).json({ error: 'Access denied' });

    res.json(prop);
  } catch {
    res.status(500).json({ error: 'Failed to fetch property' });
  }
});

// POST /properties
router.post('/', requireRole('landlord'), [
  body('name').trim().notEmpty().isLength({ max: 255 }),
  body('address').trim().notEmpty(),
  body('city').optional().trim(),
  body('description').optional().trim(),
  body('image_url').optional().isURL()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { name, address, city, description, image_url } = req.body;
    const result = await query(
      'INSERT INTO properties (landlord_id,name,address,city,description,image_url) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.user.id, name, address, city || null, description || null, image_url || null]
    );
    await auditLog(req.user.id, 'PROPERTY_CREATED', 'properties', result.rows[0].id, { name }, req.ip);
    res.status(201).json(result.rows[0]);
  } catch {
    res.status(500).json({ error: 'Failed to create property' });
  }
});

// PUT /properties/:id
router.put('/:id', requireRole('landlord'), async (req, res) => {
  try {
    const check = await query('SELECT id FROM properties WHERE id=$1 AND landlord_id=$2', [req.params.id, req.user.id]);
    if (!check.rows[0]) return res.status(404).json({ error: 'Property not found' });

    const { name, address, city, description, image_url } = req.body;
    const result = await query(
      `UPDATE properties SET
        name        = COALESCE($1, name),
        address     = COALESCE($2, address),
        city        = COALESCE($3, city),
        description = COALESCE($4, description),
        image_url   = COALESCE($5, image_url),
        updated_at  = CURRENT_TIMESTAMP
       WHERE id = $6 AND landlord_id = $7 RETURNING *`,
      [name, address, city, description, image_url, req.params.id, req.user.id]
    );
    await auditLog(req.user.id, 'PROPERTY_UPDATED', 'properties', req.params.id, req.body, req.ip);
    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: 'Failed to update property' });
  }
});

// DELETE /properties/:id
router.delete('/:id', requireRole('landlord'), async (req, res) => {
  try {
    const result = await query(
      'DELETE FROM properties WHERE id=$1 AND landlord_id=$2 RETURNING id',
      [req.params.id, req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Property not found' });
    await auditLog(req.user.id, 'PROPERTY_DELETED', 'properties', req.params.id, {}, req.ip);
    res.json({ message: 'Property deleted' });
  } catch {
    res.status(500).json({ error: 'Failed to delete property' });
  }
});

module.exports = router;
