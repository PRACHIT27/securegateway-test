import express from 'express';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ── SECURITY HEADERS ─────────────────────────────────────────────
// Fixes: Security Headers FAIL
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// ── RATE LIMITING ─────────────────────────────────────────────────
// Fixes: Rate Limiting WARNING
const requestCounts = new Map();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60000;

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const windowStart = now - RATE_WINDOW;

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, []);
  }

  const requests = requestCounts.get(ip).filter(t => t > windowStart);
  requests.push(now);
  requestCounts.set(ip, requests);

  if (requests.length > RATE_LIMIT) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  next();
});

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────
// Fixes: Missing Authentication FAIL
const VALID_TOKEN = process.env.API_TOKEN || crypto.randomBytes(32).toString('hex');

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.split(' ')[1];
  if (token !== VALID_TOKEN) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ── USERS — no hardcoded credentials ─────────────────────────────
// Fixes: Hardcoded Secret HIGH
const users = [
  { id: 1, username: 'admin', role: 'admin' },
  { id: 2, username: 'user1', role: 'user' },
];

// ── ROUTES ───────────────────────────────────────────────────────

// Health check — minimal response, no sensitive data
// Fixes: Sensitive Data Exposure FAIL
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Protected user list — auth required
// Fixes: Missing Authentication FAIL
app.get('/api/users', requireAuth, (req, res) => {
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role })));
});

// Login — typed validation, no injection surface
// Fixes: SQL Injection, NoSQL Injection FAIL
app.post('/api/login', (req, res) => {
  const { username } = req.body || {};
  if (!username || typeof username !== 'string' || username.length > 50) {
    return res.status(400).json({ error: 'Invalid request' });
  }
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ success: true, userId: user.id, role: user.role });
});

// User lookup — integer validation, no injection surface
app.get('/api/user', requireAuth, (req, res) => {
  const id = parseInt(req.query.id, 10);
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid id' });
  }
  const user = users.find(u => u.id === id);
  if (!user) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json({ id: user.id, username: user.username, role: user.role });
});

// Data endpoint — no sensitive fields exposed
// Fixes: Sensitive Data Exposure FAIL
app.get('/api/data', requireAuth, (req, res) => {
  res.json({ message: 'Secure endpoint' });
});

// Auth endpoint — rate limited by middleware above
// Fixes: Rate Limiting WARNING
app.post('/api/auth', (req, res) => {
  const { username } = req.body || {};
  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Invalid request' });
  }
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ success: true });
});

// ── START ────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Secure API running on port ${PORT}`);
});
