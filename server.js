const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'tournament.db');

let db;

// ── Middleware ──
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'ramadan-tournament-2026-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24h
}));

// ── Database Init ──
async function initDB() {
    const SQL = await initSqlJs();

    if (fs.existsSync(DB_PATH)) {
        const buffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(buffer);
    } else {
        db = new SQL.Database();
    }

    db.run(`
        CREATE TABLE IF NOT EXISTS participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            game TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            created_at DATETIME DEFAULT (datetime('now','localtime')),
            status TEXT DEFAULT 'active'
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT (datetime('now','localtime'))
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS tournaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game TEXT NOT NULL,
            name TEXT NOT NULL,
            max_players INTEGER DEFAULT 32,
            start_date TEXT,
            status TEXT DEFAULT 'upcoming',
            prize TEXT DEFAULT '',
            created_at DATETIME DEFAULT (datetime('now','localtime'))
        )
    `);

    // Create default admin: admin / admin123
    const adminCheck = db.exec("SELECT COUNT(*) as c FROM admins");
    if (adminCheck[0].values[0][0] === 0) {
        const hash = bcrypt.hashSync('admin123', 10);
        db.run("INSERT INTO admins (username, password) VALUES (?, ?)", ['admin', hash]);
        console.log('✅ Admin par défaut créé: admin / admin123');
    }

    saveDB();
    console.log('✅ Base de données initialisée');
}

function saveDB() {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
}

// ── Auth Middleware ──
function requireAdmin(req, res, next) {
    if (req.session && req.session.admin) return next();
    res.status(401).json({ error: 'Non autorisé — connectez-vous' });
}

// ══════════════════════════════════════════
//  PUBLIC API
// ══════════════════════════════════════════

// Register a participant
app.post('/api/register', (req, res) => {
    const { name, game, email, phone } = req.body;

    if (!name || !game) {
        return res.status(400).json({ error: 'Le nom et le jeu sont requis' });
    }

    if (name.trim().length < 2 || name.trim().length > 40) {
        return res.status(400).json({ error: 'Le nom doit contenir entre 2 et 40 caractères' });
    }

    // Check duplicate
    const dup = db.exec("SELECT COUNT(*) FROM participants WHERE LOWER(name)=LOWER(?) AND LOWER(game)=LOWER(?) AND status='active'", [name.trim(), game.trim()]);
    if (dup[0].values[0][0] > 0) {
        return res.status(409).json({ error: 'Tu es déjà inscrit à ce jeu !' });
    }

    db.run("INSERT INTO participants (name, game, email, phone) VALUES (?, ?, ?, ?)",
        [name.trim(), game.trim(), (email || '').trim(), (phone || '').trim()]);
    saveDB();

    const last = db.exec("SELECT last_insert_rowid()");
    const id = last[0].values[0][0];

    res.status(201).json({ success: true, message: `${name} inscrit à ${game} avec succès !`, id });
});

// Get all participants (public - limited info)
app.get('/api/participants', (req, res) => {
    const rows = db.exec("SELECT id, name, game, created_at FROM participants WHERE status='active' ORDER BY created_at DESC");
    const participants = rows.length ? rows[0].values.map(r => ({
        id: r[0], name: r[1], game: r[2], created_at: r[3]
    })) : [];
    res.json(participants);
});

// Get game statistics
app.get('/api/stats', (req, res) => {
    const total = db.exec("SELECT COUNT(*) FROM participants WHERE status='active'");
    const games = db.exec("SELECT game, COUNT(*) as count FROM participants WHERE status='active' GROUP BY game ORDER BY count DESC");
    const today = db.exec("SELECT COUNT(*) FROM participants WHERE status='active' AND DATE(created_at)=DATE('now','localtime')");

    const gameStats = games.length ? games[0].values.map(r => ({ game: r[0], count: r[1] })) : [];

    res.json({
        totalPlayers: total[0].values[0][0],
        totalGames: gameStats.length,
        topGame: gameStats.length ? gameStats[0].game : '—',
        todayCount: today[0].values[0][0],
        gameRankings: gameStats
    });
});

// Get tournaments (public)
app.get('/api/tournaments', (req, res) => {
    const rows = db.exec("SELECT * FROM tournaments ORDER BY created_at DESC");
    if (!rows.length) return res.json([]);
    const cols = rows[0].columns;
    const tournaments = rows[0].values.map(r => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = r[i]);
        return obj;
    });
    res.json(tournaments);
});

// ══════════════════════════════════════════
//  ADMIN API
// ══════════════════════════════════════════

// Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Identifiants requis' });
    }

    const rows = db.exec("SELECT id, username, password FROM admins WHERE username=?", [username]);
    if (!rows.length || !rows[0].values.length) {
        return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    const admin = { id: rows[0].values[0][0], username: rows[0].values[0][1], passwordHash: rows[0].values[0][2] };

    if (!bcrypt.compareSync(password, admin.passwordHash)) {
        return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    req.session.admin = { id: admin.id, username: admin.username };
    res.json({ success: true, message: 'Connecté !', admin: { id: admin.id, username: admin.username } });
});

// Admin Logout
app.post('/api/admin/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Check admin session
app.get('/api/admin/me', (req, res) => {
    if (req.session && req.session.admin) {
        return res.json({ authenticated: true, admin: req.session.admin });
    }
    res.json({ authenticated: false });
});

// Get all participants (admin - full info)
app.get('/api/admin/participants', requireAdmin, (req, res) => {
    const rows = db.exec("SELECT * FROM participants ORDER BY created_at DESC");
    if (!rows.length) return res.json([]);
    const cols = rows[0].columns;
    const participants = rows[0].values.map(r => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = r[i]);
        return obj;
    });
    res.json(participants);
});

// Delete participant
app.delete('/api/admin/participants/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    db.run("DELETE FROM participants WHERE id=?", [parseInt(id)]);
    saveDB();
    res.json({ success: true, message: 'Participant supprimé' });
});

// Update participant status
app.patch('/api/admin/participants/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    const { status, name, game } = req.body;
    if (status) db.run("UPDATE participants SET status=? WHERE id=?", [status, parseInt(id)]);
    if (name) db.run("UPDATE participants SET name=? WHERE id=?", [name.trim(), parseInt(id)]);
    if (game) db.run("UPDATE participants SET game=? WHERE id=?", [game.trim(), parseInt(id)]);
    saveDB();
    res.json({ success: true, message: 'Participant mis à jour' });
});

// Admin dashboard stats
app.get('/api/admin/dashboard', requireAdmin, (req, res) => {
    const total = db.exec("SELECT COUNT(*) FROM participants");
    const active = db.exec("SELECT COUNT(*) FROM participants WHERE status='active'");
    const banned = db.exec("SELECT COUNT(*) FROM participants WHERE status='banned'");
    const today = db.exec("SELECT COUNT(*) FROM participants WHERE DATE(created_at)=DATE('now','localtime')");
    const games = db.exec("SELECT game, COUNT(*) as c FROM participants WHERE status='active' GROUP BY game ORDER BY c DESC");
    const recent = db.exec("SELECT id, name, game, created_at, status FROM participants ORDER BY created_at DESC LIMIT 10");
    const daily = db.exec("SELECT DATE(created_at) as day, COUNT(*) as c FROM participants GROUP BY DATE(created_at) ORDER BY day DESC LIMIT 14");

    const gameStats = games.length ? games[0].values.map(r => ({ game: r[0], count: r[1] })) : [];
    const recentList = recent.length ? recent[0].values.map(r => ({
        id: r[0], name: r[1], game: r[2], created_at: r[3], status: r[4]
    })) : [];
    const dailyStats = daily.length ? daily[0].values.map(r => ({ date: r[0], count: r[1] })) : [];

    res.json({
        total: total[0].values[0][0],
        active: active[0].values[0][0],
        banned: banned[0].values[0][0],
        today: today[0].values[0][0],
        gameRankings: gameStats,
        recentRegistrations: recentList,
        dailyStats
    });
});

// CRUD Tournaments
app.post('/api/admin/tournaments', requireAdmin, (req, res) => {
    const { game, name, max_players, start_date, prize } = req.body;
    if (!game || !name) return res.status(400).json({ error: 'Nom et jeu requis' });
    db.run("INSERT INTO tournaments (game, name, max_players, start_date, prize) VALUES (?,?,?,?,?)",
        [game, name, max_players || 32, start_date || '', prize || '']);
    saveDB();
    res.status(201).json({ success: true, message: 'Tournoi créé' });
});

app.delete('/api/admin/tournaments/:id', requireAdmin, (req, res) => {
    db.run("DELETE FROM tournaments WHERE id=?", [parseInt(req.params.id)]);
    saveDB();
    res.json({ success: true });
});

app.patch('/api/admin/tournaments/:id', requireAdmin, (req, res) => {
    const { status } = req.body;
    if (status) db.run("UPDATE tournaments SET status=? WHERE id=?", [status, parseInt(req.params.id)]);
    saveDB();
    res.json({ success: true });
});

// Export participants as CSV
app.get('/api/admin/export/csv', requireAdmin, (req, res) => {
    const rows = db.exec("SELECT id, name, game, email, phone, created_at, status FROM participants ORDER BY created_at DESC");
    let csv = 'ID,Nom,Jeu,Email,Téléphone,Date inscription,Statut\n';
    if (rows.length) {
        rows[0].values.forEach(r => {
            csv += r.map(v => `"${(v || '').toString().replace(/"/g, '""')}"`).join(',') + '\n';
        });
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=participants_ramadan_2026.csv');
    res.send('\uFEFF' + csv);
});

// Change admin password
app.post('/api/admin/change-password', requireAdmin, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Mots de passe requis' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Minimum 6 caractères' });

    const rows = db.exec("SELECT password FROM admins WHERE id=?", [req.session.admin.id]);
    if (!bcrypt.compareSync(currentPassword, rows[0].values[0][0])) {
        return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    db.run("UPDATE admins SET password=? WHERE id=?", [hash, req.session.admin.id]);
    saveDB();
    res.json({ success: true, message: 'Mot de passe modifié' });
});

// ── Serve Pages ──
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ── Start Server ──
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`\n🌙 ══════════════════════════════════════════`);
        console.log(`   Tournoi Ramadan 2026 — Serveur démarré`);
        console.log(`   🌐 Site:  http://localhost:${PORT}`);
        console.log(`   🔐 Admin: http://localhost:${PORT}/admin`);
        console.log(`   👤 Login: admin / admin123`);
        console.log(`🌙 ══════════════════════════════════════════\n`);
    });
});
