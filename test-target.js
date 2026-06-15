// test-target.js — cleaner version for pentest demo
import express from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Fake database — no hardcoded passwords
const users = [
  { id: 1, username: 'admin', role: 'admin' },
  { id: 2, username: 'user1', role: 'user' }
];

// VULNERABILITY 1: No authentication
app.get('/api/users', (req, res) => {
  res.json(users);
});

// VULNERABILITY 2: No rate limiting
app.post('/api/auth', (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);
  if (user) {
    res.json({ success: true, token: 'fake-token' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// VULNERABILITY 3: Missing security headers
app.get('/api/data', (req, res) => {
  res.json({ data: 'some data' });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'running' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
