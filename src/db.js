import fs from 'node:fs';
import pg from 'pg';
import { config } from './config.js';

// Return bigint (COUNT, SUM) as numbers; our counts stay far below 2^53.
pg.types.setTypeParser(20, (v) => Number(v));
// Keep DATE columns as plain 'YYYY-MM-DD' strings so time zones never shift a day.
pg.types.setTypeParser(1082, (v) => v);

// DB_PASSWORD (with DB_HOST etc.) wins over DATABASE_URL, so a password with / + = or @ needs no URL escaping.
const conn = process.env.DB_PASSWORD
  ? { host: process.env.DB_HOST || 'postgres', port: Number(process.env.DB_PORT || 5432), user: process.env.DB_USER || 'cm',
      password: process.env.DB_PASSWORD, database: process.env.DB_NAME || 'cm' }
  : { connectionString: config.databaseUrl };
/**
 * TLS to Postgres. With DATABASE_SSL=true the server certificate is verified: against DATABASE_SSL_CA (a PEM file,
 * e.g. the RDS bundle) when given, else the system CAs. DATABASE_SSL_INSECURE=true skips verification (encrypted
 * but open to a man in the middle); it is logged as a warning on every start so it is not left on by accident.
 */
export function sslOptionsFor({ ssl, env = process.env, warn = (m) => console.error(JSON.stringify({ level: 'warn', msg: m })) }) {
  if (!ssl) return undefined;
  if (env.DATABASE_SSL_INSECURE === 'true') {
    warn('DATABASE_SSL_INSECURE=true: the database certificate is not verified');
    return { rejectUnauthorized: false }; // nosemgrep: bypass-tls-verification -- explicit, logged opt-out
  }
  const ca = env.DATABASE_SSL_CA;
  return { rejectUnauthorized: true, ...(ca ? { ca: fs.readFileSync(ca, 'utf8') } : {}) };
}
const sslOptions = () => sslOptionsFor({ ssl: config.databaseSsl });
export const pool = new pg.Pool({
  ...conn,
  max: Number(process.env.DATABASE_POOL_MAX || 10),
  ssl: sslOptions(),
});
pool.on('error', (e) => console.error(JSON.stringify({ level: 'error', msg: 'pg pool error', error: e.message })));

export const query = (text, params) => pool.query(text, params);

export async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

export async function closePool() {
  await pool.end();
}
