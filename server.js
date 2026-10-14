/**
 * Sentinel // Firewall Dashboard Backend
 * Node.js & Express with SQLite Database for Auth, 500 Logs, and Analytics
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// --- SQLite Database Setup ---
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new DatabaseSync(dbPath);

// 1. Users Table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'Security Analyst',
    created_at TEXT NOT NULL
  );
`);

// 2. Firewall Logs Table
db.exec(`
  CREATE TABLE IF NOT EXISTS firewall_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    firewall TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    service TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    rule TEXT NOT NULL,
    packets INTEGER,
    bytes INTEGER,
    tcp_flags TEXT,
    src_zone TEXT,
    dst_zone TEXT,
    severity TEXT,
    attack TEXT,
    raw_log TEXT
  );
`);

const logColumns = new Set(db.prepare('PRAGMA table_info(firewall_logs)').all().map(column => column.name));
if (!logColumns.has('investigation_status')) {
  db.exec("ALTER TABLE firewall_logs ADD COLUMN investigation_status TEXT NOT NULL DEFAULT 'New'");
}
if (!logColumns.has('investigation_notes')) {
  db.exec("ALTER TABLE firewall_logs ADD COLUMN investigation_notes TEXT NOT NULL DEFAULT ''");
}
if (!logColumns.has('investigation_updated_at')) {
  db.exec('ALTER TABLE firewall_logs ADD COLUMN investigation_updated_at TEXT');
}

// Helper: SHA-256 password hash
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Helper: Seed 500 firewall records into SQLite if empty
try {
  const countRow = db.prepare('SELECT COUNT(*) as count FROM firewall_logs').get();
  if (countRow.count === 0) {
    const rawData = fs.readFileSync(path.join(__dirname, 'data.json'), 'utf-8');
    const parsed = JSON.parse(rawData);
    const records = parsed.records || [];

    const insertStmt = db.prepare(`
      INSERT INTO firewall_logs (
        id, timestamp, firewall, src_ip, src_port, dst_ip, dst_port,
        protocol, service, action, status, rule, packets, bytes,
        tcp_flags, src_zone, dst_zone, severity, attack, raw_log
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?
      )
    `);

    for (const r of records) {
      insertStmt.run(
        r.id, r.timestamp, r.firewall || 'FW-EDGE-01', r.src_ip, r.src_port, r.dst_ip, r.dst_port,
        r.protocol, r.service, r.action, r.status, r.rule, r.packets, r.bytes,
        r.tcp_flags, r.src_zone, r.dst_zone, r.severity, r.attack || null, r.raw_log
      );
    }
    console.log(`[DB] Successfully seeded ${records.length} firewall logs into SQLite table 'firewall_logs'.`);
  } else {
    console.log(`[DB] SQLite contains ${countRow.count} firewall logs.`);
  }
} catch (err) {
  console.error('[DB] Seeding error:', err.message);
}

// =========================================================================
// API ENDPOINTS
// =========================================================================

// 1. User Registration
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Please provide name, email, and password.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
  if (existing) {
    return res.status(400).json({ error: 'An account with this email already exists.' });
  }

  const result = db.prepare(`
    INSERT INTO users (name, email, password_hash, role, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(name.trim(), cleanEmail, hashPassword(password), 'Security Analyst', new Date().toISOString());

  res.status(201).json({
    message: 'User registered successfully',
    user: { id: Number(result.lastInsertRowid), name: name.trim(), email: cleanEmail }
  });
});

// 2. User Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide email and password.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT id, name, email, password_hash FROM users WHERE email = ?').get(cleanEmail);

  if (!user || user.password_hash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  res.json({
    message: 'Login successful',
    user: { id: user.id, name: user.name, email: user.email }
  });
});

// 3. Get Paginated Logs directly from SQLite (500 records, 25 per page)
app.get('/api/logs', (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.max(1, parseInt(req.query.limit || '25', 10));
    const offset = (page - 1) * limit;
    const status = req.query.status;
    const search = req.query.search ? req.query.search.trim().toLowerCase() : '';

    let whereClauses = [];
    let params = [];

    if (status && status !== 'ALL') {
      whereClauses.push('status = ?');
      params.push(status);
    }

    if (search) {
      whereClauses.push('(LOWER(id) LIKE ? OR LOWER(timestamp) LIKE ? OR LOWER(src_ip) LIKE ? OR CAST(src_port AS TEXT) LIKE ? OR LOWER(dst_ip) LIKE ? OR CAST(dst_port AS TEXT) LIKE ? OR LOWER(protocol) LIKE ? OR LOWER(service) LIKE ? OR LOWER(rule) LIKE ? OR LOWER(action) LIKE ? OR LOWER(status) LIKE ? OR LOWER(severity) LIKE ? OR LOWER(COALESCE(attack, \'\')) LIKE ?)');
      const pattern = `%${search}%`;
      params.push(pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    // Total filtered count
    const countQuery = `SELECT COUNT(*) as count FROM firewall_logs ${whereSql}`;
    const totalCount = db.prepare(countQuery).get(...params).count;

    // Global summary counts
    const totalAll = db.prepare('SELECT COUNT(*) as count FROM firewall_logs').get().count;
    const totalSuccess = db.prepare("SELECT COUNT(*) as count FROM firewall_logs WHERE status = 'Success'").get().count;
    const totalFailed = db.prepare("SELECT COUNT(*) as count FROM firewall_logs WHERE status = 'Failed'").get().count;

    // Paginated rows
    const dataQuery = `SELECT * FROM firewall_logs ${whereSql} ORDER BY id ASC LIMIT ? OFFSET ?`;
    const rows = db.prepare(dataQuery).all(...params, limit, offset);

    res.json({
      summary: {
        total_records: totalAll,
        success_count: totalSuccess,
        failed_count: totalFailed
      },
      pagination: {
        page,
        limit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limit)
      },
      records: rows
    });
  } catch (err) {
    console.error('Error fetching logs:', err);
    res.status(500).json({ error: 'Database error: ' + err.message });
  }
});

// 4. Get Single Log by ID (Used by Click-to-Inspect Modal)
app.get('/api/logs/:id', (req, res) => {
  try {
    const log = db.prepare('SELECT * FROM firewall_logs WHERE id = ?').get(req.params.id);
    if (!log) {
      return res.status(404).json({ error: 'Log not found' });
    }
    res.json(log);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.patch('/api/logs/:id/investigation', (req, res) => {
  const { status, notes } = req.body || {};
  const allowedStatuses = new Set(['New', 'Investigating', 'Resolved']);

  if (!allowedStatuses.has(status)) {
    return res.status(400).json({ error: 'Status must be New, Investigating, or Resolved.' });
  }
  if (typeof notes !== 'string' || notes.length > 2000) {
    return res.status(400).json({ error: 'Notes must be text no longer than 2000 characters.' });
  }

  try {
    const result = db.prepare(`
      UPDATE firewall_logs
      SET investigation_status = ?, investigation_notes = ?, investigation_updated_at = ?
      WHERE id = ?
    `).run(status, notes.trim(), new Date().toISOString(), req.params.id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Log not found.' });
    }

    res.json({
      id: req.params.id,
      investigation_status: status,
      investigation_notes: notes.trim(),
      investigation_updated_at: db.prepare('SELECT investigation_updated_at FROM firewall_logs WHERE id = ?').get(req.params.id).investigation_updated_at
    });
  } catch (err) {
    console.error('Error saving investigation:', err);
    res.status(500).json({ error: 'Could not save investigation.' });
  }
});

// 5. Analytics Aggregations for Graphs Page
app.get('/api/analytics', (req, res) => {
  try {
    // 1. Status Ratio (Success vs Failed)
    const statusCounts = db.prepare(`
      SELECT status, COUNT(*) as count 
      FROM firewall_logs 
      GROUP BY status
    `).all();

    // 2. Top Services
    const serviceCounts = db.prepare(`
      SELECT service, dst_port as port, COUNT(*) as count 
      FROM firewall_logs 
      GROUP BY service, dst_port 
      ORDER BY count DESC 
      LIMIT 8
    `).all();

    // 3. Protocol Breakdown
    const protoCounts = db.prepare(`
      SELECT protocol, COUNT(*) as count 
      FROM firewall_logs 
      GROUP BY protocol
    `).all();

    // 4. Top Attack Signatures
    const attackCounts = db.prepare(`
      SELECT attack, COUNT(*) as count 
      FROM firewall_logs 
      WHERE attack IS NOT NULL 
      GROUP BY attack 
      ORDER BY count DESC 
      LIMIT 8
    `).all();

    // 5. Severity distribution
    const sevCounts = db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM firewall_logs 
      GROUP BY severity
    `).all();

    res.json({
      status_distribution: statusCounts,
      top_services: serviceCounts,
      protocols: protoCounts,
      attacks: attackCounts,
      severities: sevCounts
    });
  } catch (err) {
    res.status(500).json({ error: 'Analytics query error' });
  }
});

// Start the server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`🛡️  FIREWALL DASHBOARD SERVER STARTED`);
    console.log(`👉 http://localhost:${PORT}`);
    console.log(`💾 Database: SQLite (database.sqlite)`);
    console.log(`======================================================\n`);
  });
}

module.exports = app;
