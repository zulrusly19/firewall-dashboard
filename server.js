/**
 * Sentinel // Firewall Dashboard Backend
 * Node.js & Express with SQLite Database for Auth, 500 Logs, and Analytics
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { neon } = require('@neondatabase/serverless');

const app = express();
const PORT = process.env.PORT || 3000;
const useNeon = Boolean(process.env.DATABASE_URL);
const neonSql = useNeon ? neon(process.env.DATABASE_URL) : null;
let db = null;

if (!useNeon) {
  const { DatabaseSync } = require('node:sqlite');
  db = new DatabaseSync(path.join(__dirname, 'database.sqlite'));
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function toPostgresPlaceholders(statement) {
  let index = 0;
  return statement.replace(/\?/g, () => `$${++index}`);
}

async function queryRows(statement, params = []) {
  if (useNeon) {
    return neonSql.query(toPostgresPlaceholders(statement), params);
  }
  return db.prepare(statement).all(...params);
}

async function queryOne(statement, params = []) {
  if (useNeon) {
    const rows = await neonSql.query(toPostgresPlaceholders(statement), params);
    return rows[0];
  }
  return db.prepare(statement).get(...params);
}

let databaseReady;

async function initializeDatabase() {
  if (databaseReady) return databaseReady;

  databaseReady = (async () => {
    if (useNeon) {
      await neonSql.query(`
        CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT DEFAULT 'Security Analyst',
          created_at TEXT NOT NULL
        )
      `);
      await neonSql.query(`
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
          raw_log TEXT,
          investigation_status TEXT NOT NULL DEFAULT 'New',
          investigation_notes TEXT NOT NULL DEFAULT '',
          investigation_updated_at TEXT
        )
      `);
    } else {
      db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT DEFAULT 'Security Analyst',
          created_at TEXT NOT NULL
        );
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
    }

    const countRow = await queryOne('SELECT COUNT(*) AS count FROM firewall_logs');
    if (Number(countRow.count) === 0) {
      const parsed = JSON.parse(fs.readFileSync(path.join(__dirname, 'data.json'), 'utf-8'));
      const records = parsed.records || [];
      const columns = [
        'id', 'timestamp', 'firewall', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'protocol', 'service', 'action', 'status', 'rule', 'packets', 'bytes',
        'tcp_flags', 'src_zone', 'dst_zone', 'severity', 'attack', 'raw_log'
      ];
      const values = records.map(record => [
        record.id, record.timestamp, record.firewall || 'FW-EDGE-01', record.src_ip, record.src_port,
        record.dst_ip, record.dst_port, record.protocol, record.service, record.action, record.status,
        record.rule, record.packets, record.bytes, record.tcp_flags, record.src_zone, record.dst_zone,
        record.severity, record.attack || null, record.raw_log
      ]);

      if (useNeon && values.length > 0) {
        const params = values.flat();
        const placeholders = values.map((_, rowIndex) => {
          const offset = rowIndex * columns.length;
          return `(${columns.map((__, columnIndex) => `$${offset + columnIndex + 1}`).join(', ')})`;
        });
        await neonSql.query(
          `INSERT INTO firewall_logs (${columns.join(', ')}) VALUES ${placeholders.join(', ')} ON CONFLICT (id) DO NOTHING`,
          params
        );
      } else if (values.length > 0) {
        const insertStatement = db.prepare(`
          INSERT INTO firewall_logs (${columns.join(', ')})
          VALUES (${columns.map(() => '?').join(', ')})
        `);
        for (const valuesForRecord of values) insertStatement.run(...valuesForRecord);
      }
      console.log(`[DB] Seeded ${values.length} firewall logs into ${useNeon ? 'Neon Postgres' : 'SQLite'}.`);
    }
  })().catch(error => {
    databaseReady = null;
    throw error;
  });

  return databaseReady;
}

app.use('/api', async (req, res, next) => {
  try {
    await initializeDatabase();
    next();
  } catch (error) {
    console.error('Database initialization failed:', error);
    res.status(500).json({ error: 'Database initialization failed. Check the server logs.' });
  }
});

// Helper: SHA-256 password hash
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// =========================================================================
// API ENDPOINTS
// =========================================================================

// 1. User Registration
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Please provide name, email, and password.' });
  }

  try {
    const cleanEmail = email.trim().toLowerCase();
    const existing = await queryOne('SELECT id FROM users WHERE email = ?', [cleanEmail]);
    if (existing) {
      return res.status(400).json({ error: 'An account with this email already exists.' });
    }

    const nameForUser = name.trim();
    const rows = await queryRows(`
      INSERT INTO users (name, email, password_hash, role, created_at)
      VALUES (?, ?, ?, ?, ?)
      RETURNING id
    `, [nameForUser, cleanEmail, hashPassword(password), 'Security Analyst', new Date().toISOString()]);

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: Number(rows[0].id), name: nameForUser, email: cleanEmail }
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Could not create the account. Check the server logs.' });
  }
});

// 2. User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide email and password.' });
  }

  try {
    const cleanEmail = email.trim().toLowerCase();
    const user = await queryOne('SELECT id, name, email, password_hash FROM users WHERE email = ?', [cleanEmail]);

    if (!user || user.password_hash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    res.json({
      message: 'Login successful',
      user: { id: Number(user.id), name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ error: 'Could not sign in. Check the server logs.' });
  }
});

// 3. Get paginated firewall logs (500 records, 25 per page)
app.get('/api/logs', async (req, res) => {
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
    const totalCount = Number((await queryOne(countQuery, params)).count);

    // Global summary counts
    const totalAll = Number((await queryOne('SELECT COUNT(*) as count FROM firewall_logs')).count);
    const totalSuccess = Number((await queryOne("SELECT COUNT(*) as count FROM firewall_logs WHERE status = 'Success'")).count);
    const totalFailed = Number((await queryOne("SELECT COUNT(*) as count FROM firewall_logs WHERE status = 'Failed'")).count);

    // Paginated rows
    const dataQuery = `SELECT * FROM firewall_logs ${whereSql} ORDER BY id ASC LIMIT ? OFFSET ?`;
    const rows = await queryRows(dataQuery, [...params, limit, offset]);

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
app.get('/api/logs/:id', async (req, res) => {
  try {
    const log = await queryOne('SELECT * FROM firewall_logs WHERE id = ?', [req.params.id]);
    if (!log) {
      return res.status(404).json({ error: 'Log not found' });
    }
    res.json(log);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.patch('/api/logs/:id/investigation', async (req, res) => {
  const { status, notes } = req.body || {};
  const allowedStatuses = new Set(['New', 'Investigating', 'Resolved']);

  if (!allowedStatuses.has(status)) {
    return res.status(400).json({ error: 'Status must be New, Investigating, or Resolved.' });
  }
  if (typeof notes !== 'string' || notes.length > 2000) {
    return res.status(400).json({ error: 'Notes must be text no longer than 2000 characters.' });
  }

  try {
    const rows = await queryRows(`
      UPDATE firewall_logs
      SET investigation_status = ?, investigation_notes = ?, investigation_updated_at = ?
      WHERE id = ?
      RETURNING investigation_updated_at
    `, [status, notes.trim(), new Date().toISOString(), req.params.id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Log not found.' });
    }

    res.json({
      id: req.params.id,
      investigation_status: status,
      investigation_notes: notes.trim(),
      investigation_updated_at: rows[0].investigation_updated_at
    });
  } catch (err) {
    console.error('Error saving investigation:', err);
    res.status(500).json({ error: 'Could not save investigation.' });
  }
});

// 5. Analytics Aggregations for Graphs Page
app.get('/api/analytics', async (req, res) => {
  try {
    // 1. Status Ratio (Success vs Failed)
    const statusCounts = await queryRows(`
      SELECT status, COUNT(*) as count
      FROM firewall_logs 
      GROUP BY status
    `);

    // 2. Top Services
    const serviceCounts = await queryRows(`
      SELECT service, dst_port as port, COUNT(*) as count
      FROM firewall_logs 
      GROUP BY service, dst_port 
      ORDER BY count DESC 
      LIMIT 8
    `);

    // 3. Protocol Breakdown
    const protoCounts = await queryRows(`
      SELECT protocol, COUNT(*) as count
      FROM firewall_logs 
      GROUP BY protocol
    `);

    // 4. Top Attack Signatures
    const attackCounts = await queryRows(`
      SELECT attack, COUNT(*) as count
      FROM firewall_logs 
      WHERE attack IS NOT NULL 
      GROUP BY attack 
      ORDER BY count DESC 
      LIMIT 8
    `);

    // 5. Severity distribution
    const sevCounts = await queryRows(`
      SELECT severity, COUNT(*) as count
      FROM firewall_logs 
      GROUP BY severity
    `);

    const withNumericCounts = rows => rows.map(row => ({ ...row, count: Number(row.count) }));

    res.json({
      status_distribution: withNumericCounts(statusCounts),
      top_services: withNumericCounts(serviceCounts),
      protocols: withNumericCounts(protoCounts),
      attacks: withNumericCounts(attackCounts),
      severities: withNumericCounts(sevCounts)
    });
  } catch (err) {
    console.error('Error fetching analytics:', err);
    res.status(500).json({ error: 'Analytics query error.' });
  }
});

// Start the server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`🛡️  FIREWALL DASHBOARD SERVER STARTED`);
    console.log(`👉 http://localhost:${PORT}`);
    console.log(`💾 Database: ${useNeon ? 'Neon Postgres' : 'SQLite (database.sqlite)'}`);
    console.log(`======================================================\n`);
  });
}

module.exports = app;
