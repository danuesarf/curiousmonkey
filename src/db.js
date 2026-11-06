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
export const pool = new pg.Pool({
  ...conn,
  max: Number(process.env.DATABASE_POOL_MAX || 10),
  ssl: config.databaseSsl ? { rejectUnauthorized: false } : undefined,
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
