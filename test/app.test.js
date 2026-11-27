import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApp } from '../src/app.js';
import { hash, encryption } from '../src/security.js';
import { validateLdap } from '../src/ldap.js';

const origin = 'http://127.0.0.1:3100';
const env = { MASTER_ADMIN_USER: 'root', MASTER_ADMIN_PASSWORD: 'a very long admin password', APP_ORIGIN: origin, ALLOW_INSECURE_LOCALHOST: '1', ENCRYPTION_KEY: randomBytes(32).toString('base64'), DATABASE_URL: 'sqlite::memory:' };
const csr = '-----BEGIN CERTIFICATE REQUEST-----\nQUJD\n-----END CERTIFICATE REQUEST-----';

test('security, ownership, reviews, encrypted settings, and retention', async t => {
  const instance = await createApp(env);
  const server = instance.app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await instance.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(path, { method = 'GET', body, cookie, csrf, requestOrigin = origin } = {}) {
    const headers = { origin: requestOrigin };
    if (cookie) headers.cookie = cookie;
    if (csrf) headers['x-csrf-token'] = csrf;
    if (body !== undefined) headers['content-type'] = 'application/json';
    const response = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const data = await response.json();
    return { status: response.status, data, cookie: response.headers.get('set-cookie')?.split(';')[0] };
  }
  assert.equal((await request('/api/me')).status, 401);
  assert.equal((await request('/api/login', { method: 'POST', requestOrigin: 'https://evil.example', body: { username: 'root', password: env.MASTER_ADMIN_PASSWORD } })).status, 403);
  assert.equal((await request('/api/login', { method: 'POST', body: { username: 'root', password: 'bad' } })).status, 401);
  const login = await request('/api/login', { method: 'POST', body: { username: 'root', password: env.MASTER_ADMIN_PASSWORD } });
  assert.equal(login.status, 200);
  const admin = { cookie: login.cookie, csrf: login.data.csrf };
  assert.equal((await request('/api/profiles', { method: 'POST', cookie: admin.cookie, body: {} })).status, 403);
  const profile = await request('/api/profiles', { ...admin, method: 'POST', body: { name: 'Internal', suffix: 'example.internal', maxHours: 24 } });
  assert.equal(profile.status, 201);
  const created = await request('/api/requests', { ...admin, method: 'POST', body: { profileId: profile.data.id, csr } });
  assert.equal(created.status, 201);
  assert.match(created.data.warning, /not been validated/);
  assert.equal((await request(`/api/requests/${created.data.id}/review`, { ...admin, method: 'POST', body: { decision: 'approved' } })).status, 409);

  async function session(identity, role, token) {
    const csrf = `${token}-csrf`;
    await instance.db.query('INSERT INTO sessions (id, username, role, csrf, expires) VALUES (?, ?, ?, ?, ?)', [hash(token), identity, role, csrf, Date.now() + 60_000]);
    return { cookie: `sid=${token}`, csrf };
  }
  const user = await session('ldap:cn=user', 'user', 'user-token');
  const approver = await session('ldap:cn=approver', 'approver', 'approver-token');
  assert.deepEqual((await request('/api/requests', user)).data, []);
  assert.equal((await request('/api/admin/settings', user)).status, 403);
  assert.equal((await request('/api/profiles', { ...user, method: 'POST', body: { name: 'a', suffix: 'example.org', maxHours: 1 } })).status, 403);
  assert.equal((await request(`/api/requests/${created.data.id}/review`, { ...user, method: 'POST', body: { decision: 'approved' } })).status, 403);
  const results = await Promise.all(['approved', 'rejected'].map(decision => request(`/api/requests/${created.data.id}/review`, { ...approver, method: 'POST', body: { decision } })));
  assert.deepEqual(results.map(x => x.status).sort(), [200, 409]);
  assert.equal((await request(`/api/requests/${created.data.id}/issue`, { ...approver, method: 'POST', body: {} })).status, 404);
  const settings = { ldap: { enabled: false, bindPassword: 'a secret bind password', groups: {} }, retentionDays: 1, title: 'Desk' };
  assert.equal((await request('/api/admin/settings', { ...admin, method: 'PUT', body: settings })).status, 200);
  const stored = (await instance.db.query('SELECT value FROM settings WHERE key = ?', ['ldap']))[0].value;
  assert.ok(!stored.includes('secret bind password'));
  assert.match(encryption(env.ENCRYPTION_KEY).open(stored), /secret bind password/);
  assert.equal((await request('/api/me', admin)).status, 401);
  await instance.db.query('UPDATE requests SET updated = ? WHERE id = ?', [Date.now() - 2 * 86_400_000, created.data.id]);
  await instance.cleanup();
  assert.equal((await instance.db.query('SELECT id FROM requests')).length, 0);
});

test('fail-closed configuration', async () => {
  await assert.rejects(() => createApp({ ...env, ENCRYPTION_KEY: 'short' }), /ENCRYPTION_KEY/);
  await assert.rejects(() => createApp({ ...env, APP_ORIGIN: 'http://example.com' }), /APP_ORIGIN/);
  assert.throws(() => validateLdap({ enabled: true, url: 'ldap://localhost', groups: {} }), /ldaps/);
  assert.throws(() => validateLdap({ enabled: true, url: 'ldaps://localhost', groups: {} }), /Incomplete/);
});
