import { Client } from 'ldapts';
import { readFile } from 'node:fs/promises';

const escapeFilter = s => s.replace(/[\0()*\\]/g, c => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);

export async function ldapLogin(config, username, password) {
  if (!password || !username || username.length > 256 || password.length > 1024) return null;
  if (!config.enabled || !config.url.startsWith('ldaps://')) return null;
  const tlsOptions = { rejectUnauthorized: true };
  if (config.caFile) tlsOptions.ca = await readFile(config.caFile);
  const client = new Client({ url: config.url, timeout: 5000, connectTimeout: 5000, tlsOptions });
  try {
    await client.bind(config.bindDN, config.bindPassword);
    const filter = config.filter.replace('{{username}}', escapeFilter(username));
    const result = await client.search(config.baseDN, { scope: 'sub', filter, sizeLimit: 2, attributes: ['dn', config.groupAttribute] });
    if (result.searchEntries.length !== 1) return null;
    const entry = result.searchEntries[0];
    await client.bind(entry.dn, password);
    const raw = entry[config.groupAttribute];
    const groups = (Array.isArray(raw) ? raw : raw ? [raw] : []).map(x => String(x).trim().toLowerCase());
    for (const role of ['admin', 'approver', 'user']) {
      if (config.groups[role] && groups.includes(config.groups[role].trim().toLowerCase())) return { role, identity: entry.dn.trim().toLowerCase() };
    }
    return null;
  } finally { await client.unbind().catch(() => {}); }
}

export function validateLdap(c) {
  if (!c || typeof c !== 'object' || typeof c.enabled !== 'boolean') throw new Error('Invalid LDAP configuration');
  const result = {
    enabled: c.enabled, url: String(c.url || ''), bindDN: String(c.bindDN || ''), bindPassword: String(c.bindPassword || ''),
    baseDN: String(c.baseDN || ''), filter: String(c.filter || ''), groupAttribute: String(c.groupAttribute || ''),
    caFile: String(c.caFile || ''), groups: Object.fromEntries(['admin', 'approver', 'user'].map(r => [r, String(c.groups?.[r] || '')]))
  };
  if (result.enabled) {
    let url; try { url = new URL(result.url); } catch { throw new Error('Invalid LDAP URL'); }
    if (url.protocol !== 'ldaps:' || url.username || url.password || (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) throw new Error('LDAP must use an ldaps:// URL without credentials or path');
    if (!result.bindDN || !result.bindPassword || !result.baseDN || !/^[a-zA-Z][a-zA-Z0-9;-]*$/.test(result.groupAttribute) || result.filter.split('{{username}}').length !== 2 || !Object.values(result.groups).some(Boolean)) throw new Error('Incomplete LDAP configuration');
  }
  if (JSON.stringify(result).length > 16000) throw new Error('LDAP configuration too large');
  return result;
}
