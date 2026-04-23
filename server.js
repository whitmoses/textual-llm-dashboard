const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 8080;

// ── Database ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS response_log (
      id          SERIAL PRIMARY KEY,
      query_index INTEGER NOT NULL,
      query_text  TEXT NOT NULL,
      llm         TEXT NOT NULL,
      response    TEXT NOT NULL,
      score       INTEGER NOT NULL,
      user_email  TEXT NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('Database ready');
}

// ── Session ───────────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ── Passport ──────────────────────────────────────────────────────────────────
passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:  'https://textual-llm-dashboard-production.up.railway.app/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails?.[0]?.value || '';
  if (!email.endsWith('@tonic.ai')) {
    return done(null, false, { message: 'Unauthorized domain' });
  }
  return done(null, { id: profile.id, email, name: profile.displayName });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());

// ── Auth routes ───────────────────────────────────────────────────────────────
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/')
);

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/login'));
});

// ── Login page ────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Tonic Textual — Sign In</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0f1117; color: #e2e8f0; min-height: 100vh;
           display: flex; align-items: center; justify-content: center; }
    .card { background: #1a1f2e; border: 1px solid #2d3748; border-radius: 16px;
            padding: 48px 40px; width: 380px; text-align: center; }
    .logo { width: 48px; height: 48px; background: #00c2a8; border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 800; font-size: 22px; color: #0f1117; margin: 0 auto 20px; }
    h1 { font-size: 20px; font-weight: 700; color: #fff; margin-bottom: 8px; }
    p { font-size: 13px; color: #718096; margin-bottom: 32px; line-height: 1.5; }
    a.btn { display: inline-flex; align-items: center; gap: 10px; background: #fff;
            color: #1a1a1a; padding: 12px 24px; border-radius: 8px; font-size: 14px;
            font-weight: 600; text-decoration: none; transition: background 0.15s; }
    a.btn:hover { background: #f0f0f0; }
    a.btn img { width: 20px; height: 20px; }
    .note { font-size: 11px; color: #4a5568; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">T</div>
    <h1>Tonic Textual</h1>
    <p>LLM Visibility Dashboard<br>Sign in with your Tonic.ai Google account to continue.</p>
    <a class="btn" href="/auth/google">
      <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" alt="Google">
      Sign in with Google
    </a>
    <div class="note">Access restricted to @tonic.ai accounts only.</div>
  </div>
</body>
</html>`);
});

// ── Auth guard ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// ── API: Save a log entry ─────────────────────────────────────────────────────
app.post('/api/log', requireAuth, async (req, res) => {
  const { query_index, query_text, llm, response, score } = req.body;
  try {
    await pool.query(
      `INSERT INTO response_log (query_index, query_text, llm, response, score, user_email)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [query_index, query_text, llm, response, score, req.user.email]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Log insert error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── API: Fetch log entries ────────────────────────────────────────────────────
app.get('/api/log', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const result = await pool.query(
      `SELECT * FROM response_log ORDER BY created_at DESC LIMIT $1`,
      [limit]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Log fetch error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── API: Clear log ────────────────────────────────────────────────────────────
app.delete('/api/log', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM response_log');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Static files (protected) ──────────────────────────────────────────────────
app.use(requireAuth, express.static(path.join(__dirname, 'public')));

app.get('*', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────
initDb().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
