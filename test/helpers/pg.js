// Tests never reach real AWS: no instance-metadata credential lookups (on CI runners those can hang the process).
process.env.AWS_EC2_METADATA_DISABLED = 'true';

// Throwaway real Postgres for tests, using the binaries bundled by embedded-postgres.
// Postgres refuses to run as root, so in this sandbox run the tests as the `postgres` user:
//   su postgres -s /bin/bash -c "cd <repo> && node --test --test-concurrency=1 test/"
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import pg from 'pg';


function binDir() {
  if (process.env.PG_BIN) return process.env.PG_BIN;
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
  return path.join(root, 'node_modules', '@embedded-postgres', 'linux-x64', 'native', 'bin');
}

export async function startPg(port = 54329) {
  const bin = binDir();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-pg-'));
  const pw = path.join(dir, 'pw');
  const data = path.join(dir, 'data');
  fs.writeFileSync(pw, 'cm');
  execFileSync(path.join(bin, 'initdb'), ['-D', data, '-U', 'cm', '--auth=password', `--pwfile=${pw}`], { stdio: 'pipe' });
  execFileSync(path.join(bin, 'pg_ctl'), ['-D', data, '-l', path.join(dir, 'log'), '-w',
    '-o', `-p ${port} -k ${dir} -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off`, 'start'], { stdio: 'pipe' });
  const admin = new pg.Client({ connectionString: `postgres://cm:cm@127.0.0.1:${port}/postgres` });
  await admin.connect();
  await admin.query('CREATE DATABASE cm');
  await admin.end();
  process.env.DATABASE_URL = `postgres://cm:cm@127.0.0.1:${port}/cm`;
  return {
    url: process.env.DATABASE_URL,
    async stop() {
      try { execFileSync(path.join(bin, 'pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop'], { stdio: 'pipe' }); } catch { /* already down */ }
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
