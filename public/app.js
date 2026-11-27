let me = null;
const $ = selector => document.querySelector(selector);
const message = text => { $('#message').textContent = text; };
async function api(path, options = {}) {
  const headers = { ...options.headers };
  if (options.body) headers['Content-Type'] = 'application/json';
  if (me && options.method && options.method !== 'GET') headers['X-CSRF-Token'] = me.csrf;
  const response = await fetch('/api' + path, { ...options, headers, credentials: 'same-origin' });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
const element = (tag, text, className) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (className) el.className = className; return el; };
function showLogin() {
  me = null; $('#workspace').hidden = true; $('#login').hidden = false; $('#account').replaceChildren();
}
async function load() {
  const [profiles, requests] = await Promise.all([api('/profiles'), api('/requests')]);
  const select = $('#profiles'); select.replaceChildren();
  if (!profiles.length) select.append(element('option', 'No profiles configured'));
  for (const profile of profiles) { const opt = element('option', `${profile.name} · ${profile.suffix}`); opt.value = profile.id; select.append(opt); }
  const list = $('#requests'); list.replaceChildren();
  if (!requests.length) list.append(element('p', 'No requests yet.'));
  for (const request of requests) {
    const box = element('div', undefined, 'request'), head = element('div', undefined, 'request-head');
    head.append(element('strong', request.profile_name || 'Unknown profile'), element('span', request.status, 'badge')); box.append(head);
    box.append(element('div', `${request.owner} · ${new Date(Number(request.created)).toLocaleString()}`, 'meta'));
    const details = element('details'); details.append(element('summary', 'View unverified CSR'), element('pre', request.csr)); box.append(details);
    if (request.status === 'pending' && ['admin', 'approver'].includes(me.role) && request.owner !== me.username) {
      const actions = element('div', undefined, 'actions');
      for (const decision of ['approved', 'rejected']) {
        const button = element('button', decision === 'approved' ? 'Approve review' : 'Reject', decision === 'rejected' ? 'danger' : '');
        button.onclick = async () => { try { const result = await api(`/requests/${encodeURIComponent(request.id)}/review`, { method: 'POST', body: JSON.stringify({ decision }) }); message(result.warning); await load(); } catch (e) { message(e.message); } };
        actions.append(button);
      }
      box.append(actions);
    }
    list.append(box);
  }
}
async function enter() {
  $('#login').hidden = true; $('#workspace').hidden = false;
  const account = $('#account'); account.replaceChildren(element('span', `${me.username} · ${me.role} `));
  const logout = element('button', 'Sign out', 'secondary'); logout.onclick = async () => { try { await api('/logout', { method: 'POST' }); } finally { showLogin(); } }; account.append(logout);
  $('#admin').hidden = me.role !== 'admin';
  await load();
  if (me.role === 'admin') {
    const settings = await api('/admin/settings'), f = $('#settingsForm'), c = settings.ldap;
    $('#brandTitle').textContent = settings.title;
    document.title = settings.title;
    for (const key of ['title', 'retentionDays']) f.elements[key].value = settings[key];
    for (const key of ['url', 'baseDN', 'bindDN', 'filter', 'groupAttribute', 'caFile']) f.elements[key].value = c[key] || '';
    f.elements.enabled.checked = !!c.enabled;
    for (const role of ['admin', 'approver', 'user']) f.elements[role + 'Group'].value = c.groups?.[role] || '';
  }
}
$('#loginForm').onsubmit = async e => { e.preventDefault(); const f = e.target; try { me = await api('/login', { method: 'POST', body: JSON.stringify({ username: f.username.value, password: f.password.value }) }); f.reset(); message(''); await enter(); } catch (err) { message(err.message); } };
$('#requestForm').onsubmit = async e => { e.preventDefault(); const f = e.target; try { const result = await api('/requests', { method: 'POST', body: JSON.stringify({ profileId: f.profileId.value, csr: f.csr.value }) }); f.csr.value = ''; message(result.warning); await load(); } catch (err) { message(err.message); } };
$('#profileForm').onsubmit = async e => { e.preventDefault(); const f = e.target; try { await api('/profiles', { method: 'POST', body: JSON.stringify({ name: f.elements.name.value, suffix: f.elements.suffix.value, maxHours: Number(f.elements.maxHours.value) }) }); f.reset(); message('Profile created. It is not enforced for issuance.'); await load(); } catch (err) { message(err.message); } };
$('#settingsForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target, values = f.elements;
  const ldap = { enabled: values.enabled.checked, groups: {} };
  for (const key of ['url', 'baseDN', 'bindDN', 'bindPassword', 'filter', 'groupAttribute', 'caFile']) ldap[key] = values[key].value;
  for (const role of ['admin', 'approver', 'user']) ldap.groups[role] = values[role + 'Group'].value;
  try { await api('/admin/settings', { method: 'PUT', body: JSON.stringify({ ldap, title: values.title.value, retentionDays: Number(values.retentionDays.value) }) }); f.reset(); showLogin(); message('Settings saved. Please sign in again.'); } catch (err) { message(err.message); }
};
$('#refresh').onclick = () => load().catch(e => message(e.message));
api('/me').then(value => { me = value; return enter(); }).catch(() => showLogin());
