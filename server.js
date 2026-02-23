// ============================================
// DeeRude Staff Manager - Backend Server
// ============================================

const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'deerude.db');

let db = null;

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET || 'deerude-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        secure: false,
        httpOnly: true
    }
}));

// ============================================
// DATABASE HELPERS
// ============================================
function saveDatabase() {
    try {
        var data = db.export();
        var buffer = Buffer.from(data);
        fs.writeFileSync(DB_PATH, buffer);
    } catch (e) {
        console.error('DB Save Error:', e.message);
    }
}

function dbRun(sql, params) {
    if (!params) { params = []; }
    try {
        db.run(sql, params);
        saveDatabase();
        return true;
    } catch (e) {
        console.error('DB Run Error:', e.message);
        console.error('SQL:', sql);
        throw e;
    }
}

function dbGet(sql, params) {
    if (!params) { params = []; }
    try {
        var stmt = db.prepare(sql);
        stmt.bind(params);
        var result = null;
        if (stmt.step()) {
            result = stmt.getAsObject();
        }
        stmt.free();
        return result;
    } catch (e) {
        console.error('DB Get Error:', e.message);
        console.error('SQL:', sql);
        return null;
    }
}

function dbAll(sql, params) {
    if (!params) { params = []; }
    try {
        var stmt = db.prepare(sql);
        stmt.bind(params);
        var results = [];
        while (stmt.step()) {
            results.push(stmt.getAsObject());
        }
        stmt.free();
        return results;
    } catch (e) {
        console.error('DB All Error:', e.message);
        console.error('SQL:', sql);
        return [];
    }
}

function getLastId() {
    var row = dbGet('SELECT last_insert_rowid() as id', []);
    if (row) { return row.id; }
    return 0;
}

// ============================================
// AUTH MIDDLEWARE
// ============================================
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    var user = dbGet('SELECT role FROM users WHERE id = ?', [req.session.userId]);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    if (user.role !== 'administrator' && user.role !== 'manager' && user.role !== 'supervisor') {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
}

// ============================================
// AUTH ROUTES
// ============================================
app.post('/api/login', function (req, res) {
    try {
        var email = req.body.email;
        var password = req.body.password;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        var user = dbGet('SELECT * FROM users WHERE email = ? AND active = 1', [email]);

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        var match = bcrypt.compareSync(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        req.session.userId = user.id;

        return res.json({
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            role: user.role,
            phone: user.phone,
            rate: user.rate,
            payment_method: user.payment_method,
            payment_phone: user.payment_phone,
            payment_network: user.payment_network,
            bank_name: user.bank_name,
            bank_account: user.bank_account,
            pto_balance: user.pto_balance,
            pto_used: user.pto_used,
            hire_date: user.hire_date
        });
    } catch (e) {
        console.error('Login error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/logout', function (req, res) {
    req.session.destroy(function () {
        return res.json({ message: 'Logged out' });
    });
});

app.get('/api/me', requireAuth, function (req, res) {
    try {
        var user = dbGet('SELECT * FROM users WHERE id = ?', [req.session.userId]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        delete user.password;
        return res.json(user);
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// USER ROUTES
// ============================================
app.get('/api/users', requireAdmin, function (req, res) {
    try {
        var users = dbAll(
            'SELECT id, email, first_name, last_name, role, phone, rate, payment_method, payment_phone, payment_network, bank_name, bank_account, pto_balance, pto_used, active, hire_date FROM users WHERE active = 1 ORDER BY first_name',
            []
        );
        return res.json(users);
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/users', requireAdmin, function (req, res) {
    try {
        var b = req.body;
        if (!b.email || !b.password || !b.first_name || !b.last_name) {
            return res.status(400).json({ error: 'Email, password, first name and last name required' });
        }

        var exists = dbGet('SELECT id FROM users WHERE email = ?', [b.email]);
        if (exists) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        var hashed = bcrypt.hashSync(b.password, 10);
        dbRun(
            "INSERT INTO users (email, password, first_name, last_name, role, phone, rate, payment_method, payment_phone, payment_network, bank_name, bank_account, pto_balance, hire_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, date('now'))",
            [
                b.email, hashed, b.first_name, b.last_name,
                b.role || 'agent', b.phone || '', b.rate || 15,
                b.payment_method || 'mobile_money', b.payment_phone || '',
                b.payment_network || 'MTN', b.bank_name || '',
                b.bank_account || '', b.pto_balance || 15
            ]
        );

        var newId = getLastId();
        return res.json({ id: newId, message: 'User created successfully' });
    } catch (e) {
        console.error('Create user error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/users/:id', requireAuth, function (req, res) {
    try {
        var targetId = parseInt(req.params.id);
        var currentUser = dbGet('SELECT role FROM users WHERE id = ?', [req.session.userId]);

        if (!currentUser) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        if (currentUser.role === 'agent' && targetId !== req.session.userId) {
            return res.status(403).json({ error: 'Access denied' });
        }

        var fields = req.body;
        var allowed;
        if (currentUser.role === 'agent') {
            allowed = ['first_name', 'last_name', 'phone', 'payment_method', 'payment_phone', 'payment_network', 'bank_name', 'bank_account'];
        } else {
            allowed = ['first_name', 'last_name', 'email', 'phone', 'rate', 'role', 'payment_method', 'payment_phone', 'payment_network', 'bank_name', 'bank_account', 'pto_balance', 'pto_used', 'active'];
        }

        var updates = [];
        var values = [];
        for (var i = 0; i < allowed.length; i++) {
            var key = allowed[i];
            if (fields[key] !== undefined) {
                updates.push(key + ' = ?');
                values.push(fields[key]);
            }
        }

        if (fields.password) {
            updates.push('password = ?');
            values.push(bcrypt.hashSync(fields.password, 10));
        }

        if (updates.length === 0) {
            return res.json({ message: 'Nothing to update' });
        }

        values.push(targetId);
        dbRun('UPDATE users SET ' + updates.join(', ') + ' WHERE id = ?', values);
        return res.json({ message: 'User updated successfully' });
    } catch (e) {
        console.error('Update user error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/users/:id', requireAdmin, function (req, res) {
    try {
        dbRun('UPDATE users SET active = 0 WHERE id = ?', [parseInt(req.params.id)]);
        return res.json({ message: 'User deactivated' });
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// CLOCK ROUTES
// ============================================
app.post('/api/clock-in', requireAuth, function (req, res) {
    try {
        var userId = req.session.userId;
        var today = new Date().toISOString().split('T')[0];
        var now = new Date().toTimeString().slice(0, 5);

        var active = dbGet(
            'SELECT id FROM time_entries WHERE user_id = ? AND date = ? AND status = ?',
            [userId, today, 'active']
        );

        if (active) {
            return res.status(400).json({ error: 'Already clocked in' });
        }

        dbRun(
            'INSERT INTO time_entries (user_id, date, clock_in, status) VALUES (?, ?, ?, ?)',
            [userId, today, now, 'active']
        );

        return res.json({ id: getLastId(), clock_in: now, message: 'Clocked in successfully!' });
    } catch (e) {
        console.error('Clock in error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/clock-out', requireAuth, function (req, res) {
    try {
        var userId = req.session.userId;
        var today = new Date().toISOString().split('T')[0];
        var now = new Date().toTimeString().slice(0, 5);

        var active = dbGet(
            'SELECT * FROM time_entries WHERE user_id = ? AND date = ? AND status = ?',
            [userId, today, 'active']
        );

        if (!active) {
            return res.status(400).json({ error: 'Not clocked in' });
        }

        var parts_in = active.clock_in.split(':');
        var inH = parseInt(parts_in[0]);
        var inM = parseInt(parts_in[1]);

        var parts_out = now.split(':');
        var outH = parseInt(parts_out[0]);
        var outM = parseInt(parts_out[1]);

        var totalMinutes = (outH * 60 + outM) - (inH * 60 + inM);
        var hours = Math.round((totalMinutes / 60) * 100) / 100;
        if (hours < 0) { hours = 0; }

        dbRun(
            'UPDATE time_entries SET clock_out = ?, hours = ?, status = ? WHERE id = ?',
            [now, hours, 'completed', active.id]
        );

        return res.json({
            clock_out: now,
            hours: hours,
            message: 'Clocked out! Worked ' + hours.toFixed(2) + ' hours'
        });
    } catch (e) {
        console.error('Clock out error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/clock-status', requireAuth, function (req, res) {
    try {
        var today = new Date().toISOString().split('T')[0];
        var active = dbGet(
            'SELECT * FROM time_entries WHERE user_id = ? AND date = ? AND status = ?',
            [req.session.userId, today, 'active']
        );
        return res.json({ clocked_in: !!active, entry: active || null });
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/time-entries', requireAuth, function (req, res) {
    try {
        var userId = req.session.userId;

        if (req.query.user_id && parseInt(req.query.user_id) !== req.session.userId) {
            var cur = dbGet('SELECT role FROM users WHERE id = ?', [req.session.userId]);
            if (!cur || (cur.role !== 'administrator' && cur.role !== 'manager' && cur.role !== 'supervisor')) {
                return res.status(403).json({ error: 'Access denied' });
            }
            userId = parseInt(req.query.user_id);
        }

        var entries = dbAll(
            'SELECT * FROM time_entries WHERE user_id = ? ORDER BY date DESC, clock_in DESC LIMIT 100',
            [userId]
        );
        return res.json(entries);
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/time-entries/summary', requireAuth, function (req, res) {
    try {
        var userId = req.query.user_id ? parseInt(req.query.user_id) : req.session.userId;
        var month = req.query.month || new Date().toISOString().slice(0, 7);

        var entries = dbAll(
            'SELECT * FROM time_entries WHERE user_id = ? AND date LIKE ? AND status = ?',
            [userId, month + '%', 'completed']
        );

        var totalHours = 0;
        for (var i = 0; i < entries.length; i++) {
            totalHours += (entries[i].hours || 0);
        }

        return res.json({
            month: month,
            total_hours: Math.round(totalHours * 100) / 100,
            entries_count: entries.length,
            entries: entries
        });
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// PTO ROUTES
// ============================================
app.get('/api/pto', requireAuth, function (req, res) {
    try {
        var cur = dbGet('SELECT role FROM users WHERE id = ?', [req.session.userId]);
        var requests;

        if (cur && (cur.role === 'administrator' || cur.role === 'manager' || cur.role === 'supervisor')) {
            requests = dbAll(
                'SELECT p.*, u.first_name, u.last_name FROM pto_requests p JOIN users u ON p.user_id = u.id ORDER BY p.id DESC',
                []
            );
        } else {
            requests = dbAll(
                'SELECT * FROM pto_requests WHERE user_id = ? ORDER BY id DESC',
                [req.session.userId]
            );
        }
        return res.json(requests);
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/pto', requireAuth, function (req, res) {
    try {
        var start_date = req.body.start_date;
        var end_date = req.body.end_date;
        var reason = req.body.reason;

        if (!start_date || !end_date || !reason) {
            return res.status(400).json({ error: 'All fields required' });
        }

        var diffMs = new Date(end_date) - new Date(start_date);
        var days = Math.ceil(diffMs / 86400000) + 1;

        if (days <= 0) {
            return res.status(400).json({ error: 'End date must be after start date' });
        }

        var user = dbGet('SELECT pto_balance, pto_used FROM users WHERE id = ?', [req.session.userId]);
        var remaining = (user.pto_balance || 0) - (user.pto_used || 0);

        if (days > remaining) {
            return res.status(400).json({ error: 'Only ' + remaining + ' PTO days remaining' });
        }

        dbRun(
            'INSERT INTO pto_requests (user_id, start_date, end_date, days, reason) VALUES (?, ?, ?, ?, ?)',
            [req.session.userId, start_date, end_date, days, reason]
        );

        return res.json({ id: getLastId(), message: 'PTO request submitted' });
    } catch (e) {
        console.error('PTO error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/pto/:id', requireAdmin, function (req, res) {
    try {
        var status = req.body.status;
        var ptoId = parseInt(req.params.id);

        var pto = dbGet('SELECT * FROM pto_requests WHERE id = ?', [ptoId]);
        if (!pto) {
            return res.status(404).json({ error: 'PTO request not found' });
        }

        dbRun(
            'UPDATE pto_requests SET status = ?, approved_by = ? WHERE id = ?',
            [status, req.session.userId, ptoId]
        );

        if (status === 'approved') {
            dbRun(
                'UPDATE users SET pto_used = pto_used + ? WHERE id = ?',
                [pto.days, pto.user_id]
            );
        }

        return res.json({ message: 'PTO request ' + status });
    } catch (e) {
        console.error('PTO update error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// PAYROLL ROUTES
// ============================================
app.get('/api/payroll', requireAuth, function (req, res) {
    try {
        var cur = dbGet('SELECT role FROM users WHERE id = ?', [req.session.userId]);
        var records;

        if (cur && (cur.role === 'administrator' || cur.role === 'manager')) {
            records = dbAll(
                'SELECT p.*, u.first_name, u.last_name FROM payroll p JOIN users u ON p.user_id = u.id ORDER BY p.id DESC',
                []
            );
        } else {
            records = dbAll(
                'SELECT * FROM payroll WHERE user_id = ? ORDER BY id DESC',
                [req.session.userId]
            );
        }
        return res.json(records);
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/payroll/process', requireAdmin, function (req, res) {
    try {
        var user_id = req.body.user_id;
        var period = req.body.period;

        if (!user_id || !period) {
            return res.status(400).json({ error: 'User ID and period required' });
        }

        var user = dbGet('SELECT * FROM users WHERE id = ?', [user_id]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        var entries = dbAll(
            'SELECT * FROM time_entries WHERE user_id = ? AND date LIKE ? AND status = ?',
            [user_id, period + '%', 'completed']
        );

        var hours = 0;
        for (var i = 0; i < entries.length; i++) {
            hours += (entries[i].hours || 0);
        }

        var ptoRow = dbGet(
            'SELECT COALESCE(SUM(days),0) as total FROM pto_requests WHERE user_id = ? AND status = ? AND start_date LIKE ?',
            [user_id, 'approved', period + '%']
        );
        var ptoDays = ptoRow ? ptoRow.total : 0;

        var grossPay = Math.round(hours * user.rate * 100) / 100;
        var ptoValue = Math.round(ptoDays * 8 * user.rate * 100) / 100;
        var netPay = grossPay + ptoValue;
        var method = (user.payment_method === 'mobile_money') ? 'Mobile Money' : 'Bank';

        dbRun(
            "INSERT INTO payroll (user_id, period, hours_worked, rate, gross_pay, pto_days, pto_value, net_pay, status, method, paid_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
            [user_id, period, Math.round(hours * 100) / 100, user.rate, grossPay, ptoDays, ptoValue, netPay, 'paid', method]
        );

        return res.json({
            id: getLastId(),
            net_pay: netPay,
            message: 'Processed GH\u20B5' + netPay.toFixed(2) + ' for ' + user.first_name + ' ' + user.last_name + ' via ' + method
        });
    } catch (e) {
        console.error('Payroll error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// SCHEDULE ROUTES
// ============================================
app.get('/api/schedules', requireAuth, function (req, res) {
    try {
        var userId = req.query.user_id ? parseInt(req.query.user_id) : req.session.userId;
        var schedules = dbAll(
            'SELECT * FROM schedules WHERE user_id = ? ORDER BY day_of_week',
            [userId]
        );
        return res.json(schedules);
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/schedules', requireAdmin, function (req, res) {
    try {
        var b = req.body;
        if (!b.user_id || !b.day_of_week || !b.start_time || !b.end_time) {
            return res.status(400).json({ error: 'All fields required' });
        }

        var existing = dbGet(
            'SELECT id FROM schedules WHERE user_id = ? AND day_of_week = ?',
            [b.user_id, b.day_of_week]
        );

        if (existing) {
            dbRun(
                'UPDATE schedules SET start_time = ?, end_time = ? WHERE id = ?',
                [b.start_time, b.end_time, existing.id]
            );
        } else {
            dbRun(
                'INSERT INTO schedules (user_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, ?)',
                [b.user_id, b.day_of_week, b.start_time, b.end_time]
            );
        }

        return res.json({ message: 'Schedule updated' });
    } catch (e) {
        console.error('Schedule error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// DASHBOARD
// ============================================
app.get('/api/dashboard', requireAuth, function (req, res) {
    try {
        var userId = req.session.userId;
        var user = dbGet('SELECT * FROM users WHERE id = ?', [userId]);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        var month = new Date().toISOString().slice(0, 7);
        var today = new Date().toISOString().split('T')[0];

        var monthEntries = dbAll(
            'SELECT * FROM time_entries WHERE user_id = ? AND date LIKE ? AND status = ?',
            [userId, month + '%', 'completed']
        );

        var monthHours = 0;
        for (var i = 0; i < monthEntries.length; i++) {
            monthHours += (monthEntries[i].hours || 0);
        }

        var clockedIn = dbGet(
            'SELECT id FROM time_entries WHERE user_id = ? AND date = ? AND status = ?',
            [userId, today, 'active']
        );

        var stats = {
            month_hours: Math.round(monthHours * 100) / 100,
            estimated_pay: Math.round(monthHours * user.rate * 100) / 100,
            pto_remaining: (user.pto_balance || 0) - (user.pto_used || 0),
            clocked_in: !!clockedIn
        };

        if (user.role === 'administrator' || user.role === 'manager' || user.role === 'supervisor') {
            var agentCount = dbGet("SELECT COUNT(*) as c FROM users WHERE role = 'agent' AND active = 1", []);
            var pendingPto = dbGet("SELECT COUNT(*) as c FROM pto_requests WHERE status = 'pending'", []);
            var clockedCount = dbGet(
                "SELECT COUNT(*) as c FROM time_entries WHERE date = ? AND status = 'active'",
                [today]
            );
            stats.total_agents = agentCount ? agentCount.c : 0;
            stats.pending_pto = pendingPto ? pendingPto.c : 0;
            stats.currently_clocked = clockedCount ? clockedCount.c : 0;
        }

        return res.json(stats);
    } catch (e) {
        console.error('Dashboard error:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// SERVE FRONTEND
// ============================================
app.get('*', function (req, res) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// START SERVER
// ============================================
async function startServer() {
    try {
        console.log('Starting DeeRude Staff Manager...');
        console.log('Initializing database...');

        var SQL = await initSqlJs();

        if (fs.existsSync(DB_PATH)) {
            console.log('Loading existing database from ' + DB_PATH);
            var fileBuffer = fs.readFileSync(DB_PATH);
            db = new SQL.Database(fileBuffer);
        } else {
            console.log('Creating new database...');
            db = new SQL.Database();
        }

        // Create tables
        db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, first_name TEXT NOT NULL, last_name TEXT NOT NULL, role TEXT DEFAULT 'agent', phone TEXT, rate REAL DEFAULT 15, payment_method TEXT DEFAULT 'mobile_money', payment_phone TEXT, payment_network TEXT DEFAULT 'MTN', bank_name TEXT, bank_account TEXT, pto_balance INTEGER DEFAULT 15, pto_used INTEGER DEFAULT 0, active INTEGER DEFAULT 1, hire_date TEXT, created_at TEXT DEFAULT (datetime('now')))");

        db.run("CREATE TABLE IF NOT EXISTS time_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, date TEXT NOT NULL, clock_in TEXT, clock_out TEXT, hours REAL DEFAULT 0, status TEXT DEFAULT 'active', created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (user_id) REFERENCES users(id))");

        db.run("CREATE TABLE IF NOT EXISTS pto_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL, days INTEGER NOT NULL, reason TEXT, status TEXT DEFAULT 'pending', approved_by INTEGER, requested_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (user_id) REFERENCES users(id))");

        db.run("CREATE TABLE IF NOT EXISTS payroll (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, period TEXT NOT NULL, hours_worked REAL DEFAULT 0, rate REAL, gross_pay REAL, pto_days INTEGER DEFAULT 0, pto_value REAL DEFAULT 0, net_pay REAL, status TEXT DEFAULT 'pending', method TEXT, paid_at TEXT, created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (user_id) REFERENCES users(id))");

        db.run("CREATE TABLE IF NOT EXISTS schedules (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, day_of_week INTEGER NOT NULL, start_time TEXT, end_time TEXT, FOREIGN KEY (user_id) REFERENCES users(id))");

        console.log('Tables created.');

        // Create default admin
        var adminExists = dbGet('SELECT id FROM users WHERE role = ?', ['administrator']);
        if (!adminExists) {
            var adminHash = bcrypt.hashSync('admin123', 10);
            dbRun(
                "INSERT INTO users (email, password, first_name, last_name, role, phone, rate, payment_method, payment_phone, payment_network, pto_balance, hire_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ['admin@deerude.com', adminHash, 'Kwame', 'Asante', 'administrator', '0550109054', 50, 'mobile_money', '0550109054', 'MTN', 20, '2024-01-15']
            );
            console.log('Created admin: admin@deerude.com / admin123');
        }

        // Create default supervisor
        var supExists = dbGet('SELECT id FROM users WHERE role = ?', ['supervisor']);
        if (!supExists) {
            var supHash = bcrypt.hashSync('super123', 10);
            dbRun(
                "INSERT INTO users (email, password, first_name, last_name, role, phone, rate, payment_method, payment_phone, payment_network, pto_balance, hire_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ['super@deerude.com', supHash, 'Ama', 'Mensah', 'supervisor', '0551234567', 30, 'mobile_money', '0551234567', 'MTN', 18, '2024-03-01']
            );
            console.log('Created supervisor: super@deerude.com / super123');
        }

        // Create default agent
        var agentExists = dbGet('SELECT id FROM users WHERE role = ?', ['agent']);
        if (!agentExists) {
            var agentHash = bcrypt.hashSync('agent123', 10);
            dbRun(
                "INSERT INTO users (email, password, first_name, last_name, role, phone, rate, payment_method, payment_phone, payment_network, pto_balance, hire_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ['agent@deerude.com', agentHash, 'Kofi', 'Boateng', 'agent', '0249876543', 15, 'mobile_money', '0249876543', 'Airtel Tigo', 15, '2024-06-10']
            );
            console.log('Created agent: agent@deerude.com / agent123');
        }

        saveDatabase();
        console.log('Database ready.');

        app.listen(PORT, function () {
            console.log('');
            console.log('====================================');
            console.log('  DeeRude Staff Manager');
            console.log('====================================');
            console.log('  Server: http://localhost:' + PORT);
            console.log('');
            console.log('  Admin:      admin@deerude.com / admin123');
            console.log('  Supervisor: super@deerude.com / super123');
            console.log('  Agent:      agent@deerude.com / agent123');
            console.log('====================================');
            console.log('');
        });

    } catch (e) {
        console.error('');
        console.error('FAILED TO START SERVER:');
        console.error(e.message);
        console.error('');
        console.error('Try these fixes:');
        console.error('1. Delete node_modules folder');
        console.error('2. Run: npm install');
        console.error('3. Run: npm start');
        process.exit(1);
    }
}

startServer();