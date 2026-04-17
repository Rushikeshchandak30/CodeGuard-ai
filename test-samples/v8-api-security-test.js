// ⚠️ TEST FILE — CodeGuard AI v8.0 API Security Scanner
// Every pattern below should trigger a CG_API_* / CG_JWT_* finding.
// Open in Windsurf with CodeGuard installed — expect 15+ diagnostics.

const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// ── JWT Vulnerabilities ───────────────────────────────────────────────────────

// CG_JWT_001 — alg:none (critical: bypasses signature verification entirely)
const dangerousToken = jwt.sign({ userId: 1, role: 'admin' }, '', { algorithm: 'none' });

// CG_JWT_002 — weak/short secret (trivially brute-forceable)
const weakToken = jwt.sign({ userId: 2 }, 'secret');
const weakToken2 = jwt.sign({ userId: 3 }, '12345678');
const weakToken3 = jwt.sign({ userId: 4 }, 'password');

// CG_JWT_003 — missing expiresIn (tokens never expire → replay attacks)
const noExpiryToken = jwt.sign({ userId: 5, role: 'admin' }, process.env.JWT_SECRET);

// CG_JWT_004 — jwt.decode without verify (attacker can forge any payload)
app.get('/profile', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.decode(token);          // CRITICAL: no signature check
    res.json({ user: decoded });
});

// CG_JWT_005 — PyJWT verify=False equivalent pattern in JS comments:
// python: jwt.decode(token, options={"verify_signature": False})

// ── CORS Wildcard (CG_API_010) ────────────────────────────────────────────────

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');          // HIGH: wildcard CORS
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    next();
});

// ── Open Redirect (CG_API_011) ────────────────────────────────────────────────

app.get('/redirect', (req, res) => {
    const target = req.query.url;
    res.redirect(target);               // HIGH: unvalidated redirect → phishing
});

app.get('/login-callback', (req, res) => {
    const next = req.query.next;
    res.redirect(302, next);            // HIGH: same pattern
});

// ── BOLA / IDOR (CG_API_012 — OWASP API1:2023) ───────────────────────────────

app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    // No ownership check — any authenticated user can read any user's data
    db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, user) => {
        res.json(user);                 // HIGH: BOLA — missing authorization check
    });
});

app.get('/api/orders/:orderId', async (req, res) => {
    const order = await Order.findById(req.params.orderId); // HIGH: BOLA — no owner check
    res.json(order);
});

// ── Mass Assignment (CG_API_013 — OWASP API6:2023) ───────────────────────────

app.put('/api/users/:id', (req, res) => {
    Object.assign(user, req.body);      // CRITICAL: attacker can set role, isAdmin, etc.
    user.save();
    res.json(user);
});

app.post('/api/register', (req, res) => {
    const user = new User(req.body);    // CRITICAL: mass assignment — no field whitelist
    user.save();
    res.json(user);
});

// ── GraphQL Issues (CG_API_020) ──────────────────────────────────────────────

const { ApolloServer } = require('apollo-server');
const server = new ApolloServer({
    introspectionEnabled: true,         // HIGH: exposes full schema in production
    playground: true,                   // MEDIUM: debug UI should be disabled in prod
    // Missing: depthLimit, complexityLimit — DoS via deeply nested queries
});

// ── Insecure Deserialization (CG_API_030) ────────────────────────────────────

const serialize = require('node-serialize');
app.post('/api/deserialize', (req, res) => {
    const obj = serialize.unserialize(req.body.data); // CRITICAL: RCE via IIFE
    res.json(obj);
});

// ── CSRF cookie without secure flag (CG_API_040) ─────────────────────────────

const session = require('express-session');
app.use(session({
    secret: 'keyboard cat',
    cookie: {
        secure: false,                  // HIGH: session cookie sent over HTTP
        httpOnly: false,                // HIGH: accessible to JavaScript (XSS escalation)
        sameSite: 'none'
    }
}));

// ── SQL Injection via string concatenation (bonus — existing SAST rule) ───────

app.get('/search', (req, res) => {
    const q = req.query.q;
    db.query("SELECT * FROM products WHERE name = '" + q + "'", callback); // CRITICAL: SQLi
});

app.listen(3000);
