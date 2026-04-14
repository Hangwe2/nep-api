'use strict';

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { Pool } = require('pg');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nep-secret-change-me';

// ── Database ──────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Rate limiter (in-memory) ──────────────────────────────────────
// Blocks brute-force password guessing: 5 failed attempts = 15 min lockout
const loginAttempts = {};
const MAX_ATTEMPTS  = 5;
const LOCKOUT_MS    = 15 * 60 * 1000;

function checkRateLimit(ip) {
  const now = Date.now();
  if (!loginAttempts[ip]) {
    loginAttempts[ip] = { count: 0, firstAttempt: now, locked: false };
  }
  const rec = loginAttempts[ip];
  if (rec.locked && (now - rec.firstAttempt) > LOCKOUT_MS) {
    loginAttempts[ip] = { count: 0, firstAttempt: now, locked: false };
    return false;
  }
  if (rec.locked) return true;
  if ((now - rec.firstAttempt) > LOCKOUT_MS) {
    loginAttempts[ip] = { count: 1, firstAttempt: now, locked: false };
    return false;
  }
  rec.count++;
  if (rec.count >= MAX_ATTEMPTS) rec.locked = true;
  return rec.locked;
}

function clearRateLimit(ip) {
  delete loginAttempts[ip];
}

// ── Middleware ────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// ── Auth middleware ───────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Owner-only middleware
function ownerOnly(req, res, next) {
  if (!req.user || req.user.role !== 'Owner') {
    return res.status(403).json({ error: 'Owner access required' });
  }
  next();
}

// ── Health ────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch(e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const { username, password } = req.body;

  // Rate limit check
  if (checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many login attempts. Please wait 15 minutes.' });
  }

  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  try {
    const r = await pool.query(
      'SELECT * FROM staff WHERE LOWER(username)=$1 OR LOWER(email)=$1',
      [username.toLowerCase()]
    );
    const user = r.rows[0];
    if (!user) return res.json({ error: 'Account not found.' });

    // Support plain-text password for legacy/seeded accounts
    let valid = false;
    if (user.password_hash.startsWith('$2')) {
      valid = await bcrypt.compare(password, user.password_hash);
    } else {
      valid = (user.password_hash === password);
    }

    if (!valid) return res.json({ error: 'Incorrect password.' });
    if (user.status === 'pending')   return res.json({ pending: true });
    if (user.status === 'suspended') return res.json({ error: 'Account suspended. Contact owner.' });

    // Clear rate limit on successful login
    clearRateLimit(ip);

    // Update last login
    await pool.query(
      'UPDATE staff SET last_login=NOW(), login_count=login_count+1 WHERE id=$1',
      [user.id]
    );

    const payload = {
      id: user.id, fn: user.first_name, ln: user.last_name,
      username: user.username, role: user.role, branch: user.branch,
      permissions: user.permissions, status: user.status
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: payload });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// MEMBERS
// ══════════════════════════════════════════════════════════════════
app.get('/api/members', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM members ORDER BY id DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/members', auth, async (req, res) => {
  const { first_name, last_name, id_number, phone, email, village, plan, branch, amount, status, beneficiaries, manual_member_no } = req.body;
  if (!first_name || !last_name) return res.status(400).json({ error: 'Name required' });
  try {
    let member_no;
    if (manual_member_no && manual_member_no.trim()) {
      // Use provided policy number
      member_no = manual_member_no.trim().toUpperCase();
      const dup = await pool.query('SELECT id FROM members WHERE member_no=$1', [member_no]);
      if (dup.rows.length > 0) {
        return res.status(400).json({ error: 'Policy number ' + member_no + ' already exists.' });
      }
    } else {
      // Auto-generate from highest existing number
      const last = await pool.query(
        "SELECT member_no FROM members WHERE member_no ~ '^NEP-[0-9]+$' ORDER BY LENGTH(member_no) DESC, member_no DESC LIMIT 1"
      );
      if (last.rows.length > 0) {
        const lastNum = parseInt(last.rows[0].member_no.replace('NEP-','')) + 1;
        member_no = 'NEP-' + String(lastNum).padStart(3, '0');
      } else {
        member_no = 'NEP-001';
      }
    }

    const r = await pool.query(
      `INSERT INTO members (member_no, first_name, last_name, id_number, phone, email, village, plan, branch, amount, status, beneficiaries)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [member_no, first_name, last_name, id_number||'', phone||'', email||'', village||'', plan||'', branch||'', amount||0, status||'Active', JSON.stringify(beneficiaries||[])]
    );

    await logActivity(req.user.id, req.user.fn+' '+req.user.ln, 'Add Member', 'Added '+first_name+' '+last_name+' ('+member_no+')', 'info', pool);
    res.json(r.rows[0]);
  } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.put('/api/members/:id', auth, async (req, res) => {
  const { first_name, last_name, id_number, phone, email, village, plan, branch, amount, status, beneficiaries, paid_ahead, pay_score, overdue_count } = req.body;
  try {
    const r = await pool.query(
      `UPDATE members SET first_name=$1, last_name=$2, id_number=$3, phone=$4, email=$5, village=$6, plan=$7, branch=$8, amount=$9, status=$10, beneficiaries=$11,
       paid_ahead=COALESCE($12, paid_ahead), pay_score=COALESCE($13, pay_score), overdue_count=COALESCE($14, overdue_count)
       WHERE id=$15 RETURNING *`,
      [first_name, last_name, id_number||'', phone||'', email||'', village||'', plan||'', branch||'', amount||0, status||'Active', JSON.stringify(beneficiaries||[]),
       paid_ahead||null, pay_score||null, overdue_count||null, req.params.id]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/members/:id/pay', auth, async (req, res) => {
  const { last_pay, status, paid_ahead } = req.body;
  try {
    const r = await pool.query(
      'UPDATE members SET last_pay=$1, status=$2, paid_ahead=COALESCE($3, paid_ahead) WHERE id=$4 RETURNING *',
      [last_pay, status, paid_ahead != null ? paid_ahead : null, req.params.id]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/members/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM members WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// CLAIMS
// ══════════════════════════════════════════════════════════════════
app.get('/api/claims', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM claims ORDER BY id DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/claims', auth, async (req, res) => {
  const { member_id, type, notes, amount } = req.body;
  try {
    const cnt = await pool.query('SELECT COUNT(*) FROM claims');
    const num = String(parseInt(cnt.rows[0].count) + 25).padStart(3, '0');
    const claim_no = 'CLM-' + num;
    const today = new Date().toLocaleDateString('en-ZA', {day:'2-digit',month:'short',year:'numeric'});

    let member_name = '', plan = '';
    if (member_id) {
      const m = await pool.query('SELECT first_name, last_name, plan FROM members WHERE id=$1', [member_id]);
      if (m.rows[0]) { member_name = m.rows[0].first_name + ' ' + m.rows[0].last_name; plan = m.rows[0].plan; }
    }

    const r = await pool.query(
      'INSERT INTO claims (claim_no, member_id, member_name, plan, type, notes, amount, status, date) VALUES ($1,$2,$3,$4,$5,$6,$7,\'Pending\',$8) RETURNING *',
      [claim_no, member_id||null, member_name, plan, type||'', notes||'', amount||0, today]
    );
    res.json(r.rows[0]);
  } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.put('/api/claims/:id', auth, async (req, res) => {
  const { status } = req.body;
  try {
    const r = await pool.query('UPDATE claims SET status=$1 WHERE id=$2 RETURNING *', [status, req.params.id]);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// PAYMENTS
// ══════════════════════════════════════════════════════════════════
app.get('/api/payments', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT p.*,
             s.first_name || ' ' || s.last_name AS recorded_by_name
      FROM payments p
      LEFT JOIN staff s ON s.id = p.recorded_by
      ORDER BY p.id DESC
    `);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/payments', auth, async (req, res) => {
  const { member_id, amount, reference, date, channel } = req.body;
  try {
    let member_name = '', plan = '';
    if (member_id) {
      const m = await pool.query('SELECT first_name, last_name, plan, branch, status FROM members WHERE id=$1', [member_id]);
      if (m.rows[0]) {
        member_name = m.rows[0].first_name + ' ' + m.rows[0].last_name;
        plan = m.rows[0].plan;
        member_branch = m.rows[0].branch || '';
        const newStatus = m.rows[0].status === 'Pending' ? 'Active' : m.rows[0].status;
        await pool.query('UPDATE members SET last_pay=$1, status=$2 WHERE id=$3', [date, newStatus, member_id]);
      }
    }
    const r = await pool.query(
      `INSERT INTO payments (member_id, member_name, plan, amount, reference, date, channel, branch, recorded_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [member_id||null, member_name, plan, amount, reference||'', date||'', channel||'', member_branch, req.user.id]
    );
    await logActivity(req.user.id, req.user.fn+' '+req.user.ln, 'Payment', 'Recorded R'+amount+' for '+member_name, 'info', pool);
    res.json(r.rows[0]);
  } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ── Edit payment (Owner only) ─────────────────────────────────────
app.put('/api/payments/:id', auth, async (req, res) => {
  const { amount, reference, channel, date } = req.body;
  try {
    const r = await pool.query(
      'UPDATE payments SET amount=$1, reference=$2, channel=$3, date=$4 WHERE id=$5 RETURNING *',
      [amount, reference||'', channel||'', date||'', req.params.id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Payment not found' });
    // Update member last_pay if needed
    if (date && r.rows[0].member_id) {
      await pool.query(
        'UPDATE members SET last_pay=$1 WHERE id=$2',
        [date, r.rows[0].member_id]
      );
    }
    await logActivity(req.user.id, req.user.fn+' '+req.user.ln, 'Payment Edited', 'Payment #'+req.params.id+' updated to R'+amount, 'warning', pool);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// TASKS
// ══════════════════════════════════════════════════════════════════
app.get('/api/tasks', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM tasks ORDER BY id DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks', auth, async (req, res) => {
  const { title, description, assignee_id, priority, due_date, category } = req.body;
  try {
    let assignee_name = '';
    if (assignee_id) {
      const s = await pool.query('SELECT first_name, last_name FROM staff WHERE id=$1', [assignee_id]);
      if (s.rows[0]) assignee_name = s.rows[0].first_name + ' ' + s.rows[0].last_name;
    }
    const r = await pool.query(
      'INSERT INTO tasks (title, description, assignee_id, assignee_name, priority, due_date, category, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [title, description||'', assignee_id||null, assignee_name, priority||'medium', due_date||null, category||'Other', 'todo']
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/tasks/:id', auth, async (req, res) => {
  const { status } = req.body;
  try {
    const completed = status === 'done' ? 'NOW()' : 'NULL';
    const r = await pool.query(
      `UPDATE tasks SET status=$1, completed_at=${completed} WHERE id=$2 RETURNING *`,
      [status, req.params.id]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// PLANS
// ══════════════════════════════════════════════════════════════════
app.get('/api/plans', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM plans ORDER BY fee ASC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/plans', auth, async (req, res) => {
  const { name, fee, cashback, grocery, max_members, wait_months } = req.body;
  try {
    const r = await pool.query(
      'INSERT INTO plans (name, fee, cashback, grocery, max_members, wait_months) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [name, fee, cashback||0, grocery||false, max_members||10, wait_months||3]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/plans/:id', auth, async (req, res) => {
  const { name, fee, cashback, grocery, max_members, wait_months } = req.body;
  try {
    const r = await pool.query(
      'UPDATE plans SET name=$1, fee=$2, cashback=$3, grocery=$4, max_members=$5, wait_months=$6 WHERE id=$7 RETURNING *',
      [name, fee, cashback||0, grocery||false, max_members||10, wait_months||3, req.params.id]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// FUNERALS
// ══════════════════════════════════════════════════════════════════
app.get('/api/funerals', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM funerals ORDER BY id DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/funerals', auth, async (req, res) => {
  const { deceased_name, client_type, package: pkg, package_price, income, cover_amount, topup,
          member_id, contact_name, contact_phone, notes, dod, funeral_date, budget_lines, budget_total } = req.body;
  try {
    const cnt = await pool.query('SELECT COUNT(*) FROM funerals');
    const num = String(parseInt(cnt.rows[0].count) + 1).padStart(3, '0');
    const case_no = 'FUN-' + num;

    const r = await pool.query(
      `INSERT INTO funerals (case_no, deceased_name, client_type, package, package_price, income, cover_amount, topup,
        member_id, contact_name, contact_phone, notes, dod, funeral_date, budget_lines, budget_total)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [case_no, deceased_name, client_type||'walkin', pkg||'', package_price||0, income||0, cover_amount||0, topup||0,
       member_id||null, contact_name||'', contact_phone||'', notes||'', dod||'', funeral_date||'',
       JSON.stringify(budget_lines||[]), budget_total||0]
    );

    const today = new Date().toLocaleDateString('en-ZA', {day:'2-digit',month:'short',year:'numeric'});
    await pool.query(
      'INSERT INTO funeral_ledger (funeral_id, type, description, amount, date, recorded_by, recorded_by_name) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [r.rows[0].id, 'income', (client_type==='walkin'?'Walk-in — '+pkg:'Policy + top-up'), income||0, today, req.user.id, req.user.fn+' '+req.user.ln]
    );

    res.json(r.rows[0]);
  } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.put('/api/funerals/:id/complete', auth, async (req, res) => {
  try {
    const r = await pool.query(
      "UPDATE funerals SET status='completed', completed_at=NOW() WHERE id=$1 RETURNING *",
      [req.params.id]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/funerals/:id/expenses', auth, async (req, res) => {
  const { description, amount, budgeted, category, supplier, reference, budget_line_idx } = req.body;
  try {
    const today = new Date().toLocaleDateString('en-ZA', {day:'2-digit',month:'short',year:'numeric'});
    const variance = budgeted ? (amount - budgeted) : null;
    const r = await pool.query(
      `INSERT INTO funeral_ledger (funeral_id, type, description, amount, budgeted, variance, category, supplier, reference, budget_line_idx, date, recorded_by, recorded_by_name)
       VALUES ($1,'expense',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.params.id, description, amount, budgeted||0, variance, category||'Other', supplier||'', reference||'', budget_line_idx!==undefined?budget_line_idx:null, today, req.user.id, req.user.fn+' '+req.user.ln]
    );
    res.json(r.rows[0]);
  } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.get('/api/funerals/:id/ledger', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM funeral_ledger WHERE funeral_id=$1 ORDER BY id DESC', [req.params.id]);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// STAFF — Owner only for sensitive operations
// ══════════════════════════════════════════════════════════════════
app.get('/api/staff', auth, async (req, res) => {
  try {
    // Return staff without password hashes
    const r = await pool.query(
      'SELECT id, first_name, last_name, username, email, phone, role, branch, permissions, status, joined_at, last_login, login_count FROM staff ORDER BY id ASC'
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/staff', auth, ownerOnly, async (req, res) => {
  const { fn, ln, username, password, email, phone, role, branch, permissions } = req.body;
  if (!fn || !ln || !username || !password) return res.status(400).json({ error: 'Required fields missing' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO staff (first_name, last_name, username, password_hash, email, phone, role, branch, permissions, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active') RETURNING id, first_name, last_name, username, email, phone, role, branch, permissions, status, joined_at`,
      [fn, ln, username.toLowerCase(), hash, email||'', phone||'', role||'Agent', branch||'', JSON.stringify(permissions||[])]
    );
    await logActivity(req.user.id, req.user.fn+' '+req.user.ln, 'Staff Created', fn+' '+ln+' ('+role+')', 'info', pool);
    res.json(r.rows[0]);
  } catch(e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already exists.' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/staff/:id', auth, ownerOnly, async (req, res) => {
  const { fn, ln, username, password, email, phone, role, branch, permissions, status } = req.body;
  try {
    let query, params;
    if (password && password.length >= 4) {
      const hash = await bcrypt.hash(password, 10);
      query = 'UPDATE staff SET first_name=$1, last_name=$2, username=$3, password_hash=$4, email=$5, phone=$6, role=$7, branch=$8, permissions=$9, status=$10 WHERE id=$11 RETURNING id, first_name, last_name, username, email, role, branch, status';
      params = [fn, ln, username.toLowerCase(), hash, email||'', phone||'', role||'Agent', branch||'', JSON.stringify(permissions||[]), status||'active', req.params.id];
    } else {
      query = 'UPDATE staff SET first_name=$1, last_name=$2, username=$3, email=$4, phone=$5, role=$6, branch=$7, permissions=$8, status=$9 WHERE id=$10 RETURNING id, first_name, last_name, username, email, role, branch, status';
      params = [fn, ln, username.toLowerCase(), email||'', phone||'', role||'Agent', branch||'', JSON.stringify(permissions||[]), status||'active', req.params.id];
    }
    const r = await pool.query(query, params);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/staff/activity', auth, ownerOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM activity_log ORDER BY id DESC LIMIT 200');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Activity log helper ───────────────────────────────────────────
async function logActivity(staff_id, user_name, action, detail, level, pool) {
  try {
    await pool.query(
      'INSERT INTO activity_log (staff_id, user_name, action, detail, level) VALUES ($1,$2,$3,$4,$5)',
      [staff_id, user_name, action, detail, level||'info']
    );
  } catch(e) { /* non-critical */ }
}

// ── 404 handler ───────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`NEP API running on port ${PORT}`);
});
