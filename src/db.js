import { DatabaseSync } from 'node:sqlite';
import pg from 'pg';

export async function openDatabase(url) {
  let query, close;
  if (url.startsWith('postgres://') || url.startsWith('postgresql://')) {
    const pool = new pg.Pool({ connectionString: url });
    query = async (sql, args = []) => (await pool.query(sql.replace(/\?/g, (_, i, s) => `$${(s.slice(0, i).match(/\?/g) || []).length + 1}`), args)).rows;
    close = () => pool.end();
  } else {
    if (!url.startsWith('sqlite:')) throw new Error('DATABASE_URL must be sqlite:<path> or postgres://...');
    const db = new DatabaseSync(url.slice(7));
    db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000');
    query = async (sql, args = []) => {
      const stmt = db.prepare(sql);
      return /^\s*(SELECT|WITH)\b/i.test(sql) || /\bRETURNING\b/i.test(sql) ? stmt.all(...args) : (stmt.run(...args), []);
    };
    close = async () => db.close();
  }
  for (const sql of [
    'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL, csrf TEXT NOT NULL, expires BIGINT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, suffix TEXT NOT NULL, max_hours INTEGER NOT NULL, auto_approve INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, owner TEXT NOT NULL, profile_id TEXT NOT NULL, csr TEXT NOT NULL, status TEXT NOT NULL, reviewer TEXT, created BIGINT NOT NULL, updated BIGINT NOT NULL)'
  ]) await query(sql);
  return { query, close };
}
