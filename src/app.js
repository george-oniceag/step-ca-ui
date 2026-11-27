import express from 'express';
import { randomUUID } from 'node:crypto';
import { encryption, equal, hash, passwordMatches, random } from './security.js';
import { ldapLogin, validateLdap } from './ldap.js';
import { openDatabase } from './db.js';

export async function createApp(env = process.env) {
  const master = env.MASTER_ADMIN_USER;
  const masterPassword = env.MASTER_ADMIN_PASSWORD;
  if (!master || !masterPassword || masterPassword.length < 16 || master.length > 128) throw new Error('MASTER_ADMIN_USER and MASTER_ADMIN_PASSWORD (at least 16 characters) are required');
  const origin = new URL(env.APP_ORIGIN || '');
  if (origin.origin !== env.APP_ORIGIN || (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && env.ALLOW_INSECURE_LOCALHOST === '1' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)))) throw new Error('APP_ORIGIN must be an HTTPS origin (or explicit localhost development origin)');
  const crypt = encryption(env.ENCRYPTION_KEY);
  const db = await openDatabase(env.DATABASE_URL || 'sqlite:./app.db');
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.set({ 'Content-Security-Policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' });
    if (origin.protocol === 'https:') res.set('Strict-Transport-Security', 'max-age=31536000');
    next();
  });
  app.use(express.json({ limit: '128kb', strict: true }));
  app.use('/api', (req, res, next) => {
    if (!['GET', 'HEAD'].includes(req.method) && req.get('origin') !== origin.origin) return res.status(403).json({ error: 'Invalid origin' });
    next();
  });
  const secure = origin.protocol === 'https:';
  const cookie = (value, age) => `sid=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${secure ? '; Secure' : ''}`;
  const getSetting = async (key, fallback) => (await db.query('SELECT value FROM settings WHERE key = ?', [key]))[0]?.value ?? fallback;
  const setSetting = (key, value) => db.query('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value', [key, value]);
  const getLdap = async () => {
    const stored = await getSetting('ldap', '');
    return stored ? JSON.parse(crypt.open(stored)) : { enabled: false, groups: {} };
  };
  const limiter = new Map();
  app.post('/api/login', async (req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    for (const [k, v] of limiter) if (v.reset < now) limiter.delete(k);
    const entry = limiter.get(ip) || { count: 0, reset: now + 15 * 60_000 };
    entry.count++; limiter.set(ip, entry);
    if (entry.count > 20) return res.status(429).json({ error: 'Too many login attempts' });
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password || username.length > 256 || password.length > 1024) return res.status(401).json({ error: 'Invalid credentials' });
    let role, identity;
    if (username === master && passwordMatches(password, masterPassword)) { role = 'admin'; identity = `master:${master}`; }
    else {
      try {
        const account = await ldapLogin(await getLdap(), username, password);
        if (account) { role = account.role; identity = `ldap:${account.identity}`; }
      } catch { role = null; }
    }
    if (!role) return res.status(401).json({ error: 'Invalid credentials' });
    limiter.delete(ip);
    const token = random(), csrf = random(), expires = now + 15 * 60_000;
    await db.query('INSERT INTO sessions (id, username, role, csrf, expires) VALUES (?, ?, ?, ?, ?)', [hash(token), identity, role, csrf, expires]);
    res.set('Set-Cookie', cookie(token, 900)).json({ username: identity, role, csrf });
  });
  app.use('/api', async (req, res, next) => {
    const raw = /(?:^|;\s*)sid=([A-Za-z0-9_-]+)/.exec(req.get('cookie') || '')?.[1];
    if (!raw) return res.status(401).json({ error: 'Authentication required' });
    const session = (await db.query('SELECT * FROM sessions WHERE id = ? AND expires > ?', [hash(raw), Date.now()]))[0];
    if (!session) return res.status(401).json({ error: 'Session expired' });
    if (!['GET', 'HEAD'].includes(req.method) && !equal(req.get('x-csrf-token') || '', session.csrf)) return res.status(403).json({ error: 'Invalid CSRF token' });
    req.session = session; next();
  });
  const requireRole = (...roles) => (req, res, next) => roles.includes(req.session.role) ? next() : res.status(403).json({ error: 'Forbidden' });
  app.get('/api/me', (req, res) => res.json({ username: req.session.username, role: req.session.role, csrf: req.session.csrf }));
  app.post('/api/logout', async (req, res) => { await db.query('DELETE FROM sessions WHERE id = ?', [req.session.id]); res.set('Set-Cookie', cookie('', 0)).json({ ok: true }); });
  app.get('/api/profiles', async (req, res) => res.json(await db.query('SELECT * FROM profiles ORDER BY name')));
  app.post('/api/profiles', requireRole('admin'), async (req, res) => {
    const { name, suffix, maxHours } = req.body || {};
    if (typeof name !== 'string' || !name.trim() || name.length > 80 || typeof suffix !== 'string' || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(suffix) || suffix.length > 253 || !Number.isInteger(maxHours) || maxHours < 1 || maxHours > 8760) return res.status(400).json({ error: 'Invalid profile' });
    const id = randomUUID();
    await db.query('INSERT INTO profiles (id, name, suffix, max_hours, auto_approve) VALUES (?, ?, ?, ?, ?)', [id, name.trim(), suffix, maxHours, 0]);
    res.status(201).json({ id });
  });
  app.get('/api/requests', async (req, res) => {
    const isReviewer = ['admin', 'approver'].includes(req.session.role);
    const rows = await db.query(`SELECT r.*, p.name AS profile_name, p.suffix, p.max_hours FROM requests r LEFT JOIN profiles p ON p.id = r.profile_id ${isReviewer ? '' : 'WHERE r.owner = ?'} ORDER BY r.created DESC LIMIT 500`, isReviewer ? [] : [req.session.username]);
    res.json(rows);
  });
  app.post('/api/requests', async (req, res) => {
    const { profileId, csr } = req.body || {};
    if (typeof profileId !== 'string' || typeof csr !== 'string' || csr.length > 64_000 || !/^-----BEGIN CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE REQUEST-----\s*$/.test(csr)) return res.status(400).json({ error: 'A PEM certificate request is required' });
    if (!(await db.query('SELECT id FROM profiles WHERE id = ?', [profileId])).length) return res.status(400).json({ error: 'Unknown profile' });
    const id = randomUUID(), now = Date.now();
    await db.query('INSERT INTO requests (id, owner, profile_id, csr, status, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?)', [id, req.session.username, profileId, csr, 'pending', now, now]);
    res.status(201).json({ id, status: 'pending', warning: 'CSR has not been validated; issuance is disabled.' });
  });
  app.post('/api/requests/:id/review', requireRole('admin', 'approver'), async (req, res) => {
    if (!['approved', 'rejected'].includes(req.body?.decision)) return res.status(400).json({ error: 'Invalid decision' });
    const changed = await db.query('UPDATE requests SET status = ?, reviewer = ?, updated = ? WHERE id = ? AND status = ? AND owner <> ? RETURNING id', [req.body.decision, req.session.username, Date.now(), req.params.id, 'pending', req.session.username]);
    if (!changed.length) return res.status(409).json({ error: 'Not pending, not found, or self-review prohibited' });
    res.json({ ok: true, warning: 'Review does not issue a certificate; issuance is disabled.' });
  });
  app.get('/api/admin/settings', requireRole('admin'), async (req, res) => {
    const ldap = await getLdap(); const hasBindPassword = Boolean(ldap.bindPassword);
    delete ldap.bindPassword;
    res.json({ ldap, hasBindPassword, retentionDays: Number(await getSetting('retentionDays', '90')), title: await getSetting('title', 'Certificate desk') });
  });
  app.put('/api/admin/settings', requireRole('admin'), async (req, res) => {
    const { ldap, retentionDays, title } = req.body || {};
    if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650 || typeof title !== 'string' || !title.trim() || title.length > 80 || !ldap || typeof ldap !== 'object') return res.status(400).json({ error: 'Invalid settings' });
    let config;
    try {
      const current = await getLdap();
      config = validateLdap({ ...ldap, bindPassword: ldap.bindPassword || current.bindPassword || '' });
    } catch (e) { return res.status(400).json({ error: e.message }); }
    await setSetting('ldap', crypt.seal(JSON.stringify(config)));
    await setSetting('retentionDays', String(retentionDays));
    await setSetting('title', title.trim());
    // Role changes must not leave existing sessions authorized under stale configuration.
    await db.query('DELETE FROM sessions');
    res.json({ ok: true });
  });
  app.get('/api/public-settings', (req, res) => res.json({ issuanceEnabled: false }));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
  app.use(express.static(new URL('../public/', import.meta.url).pathname, { index: 'index.html' }));
  app.use((err, req, res, next) => { console.error('Request failed:', err.message); res.status(500).json({ error: 'Request failed' }); });
  async function cleanup() {
    const now = Date.now();
    const days = Number(await getSetting('retentionDays', '90'));
    await db.query('DELETE FROM sessions WHERE expires <= ?', [now]);
    if (Number.isInteger(days) && days >= 1 && days <= 3650) await db.query('DELETE FROM requests WHERE status <> ? AND updated < ?', ['pending', now - days * 86_400_000]);
  }
  await cleanup();
  const timer = setInterval(() => cleanup().catch(e => console.error('Retention cleanup failed:', e.message)), 60 * 60_000);
  timer.unref();
  return { app, db, cleanup, close: async () => { clearInterval(timer); await db.close(); } };
}
