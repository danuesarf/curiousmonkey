import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import { ZodError } from 'zod';
import { config, assertConfig } from './config.js';
import { query, closePool } from './db.js';
import { migrate } from './migrate.js';
import { loadSession, csrfGuard } from './auth/sessions.js';
import { auth } from './routes/auth.js';
import { data } from './routes/data.js';
import { admin } from './routes/admin.js';
import { metricsText } from './queue.js';

const pub = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

export function createApp() {
  const app = express();
  if (config.trustProxy) app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'], fontSrc: ["'self'"],
      connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"] } },
    crossOriginEmbedderPolicy: false,
  }));
  app.use(express.json({ limit: '256kb' }));

  app.get('/healthz', async (req, res) => { try { await query('SELECT 1'); res.send('ok'); } catch { res.status(503).send('db down'); } });
  app.get('/metrics', async (req, res) => {   // not exposed by the Ingress; scrape it inside the cluster
    try { res.type('text/plain; version=0.0.4').send(await metricsText()); } catch { res.status(503).end(); }
  });

  app.use('/api', loadSession, csrfGuard);
  app.use('/api/auth', auth);
  app.use('/api', data);
  app.use('/api', admin);
  app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));

  app.use(express.static(pub, { maxAge: config.env === 'production' ? '1h' : 0, index: 'index.html' }));
  app.get(/^\/(?!api).*/, (req, res) => res.sendFile(path.join(pub, 'index.html')));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err instanceof ZodError) return res.status(400).json({ error: 'invalid_input', message: err.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ') });
    if (err.status && err.status < 500) return res.status(err.status).json({ error: err.code || 'error', message: err.message, field: err.field });
    console.error(JSON.stringify({ level: 'error', msg: err.message, path: req.path, stack: err.stack?.split('\n').slice(0, 4) }));
    res.status(500).json({ error: 'server_error', message: 'Something went wrong on our side.' });
  });
  return app;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  assertConfig();
  if (process.env.RUN_MIGRATIONS !== 'false') await migrate((m) => console.log(JSON.stringify({ level: 'info', msg: m })));
  // event names a newer version knows how to map: settle them now, so the Unidentified list is right before the next scan
  try { const n = await (await import('./analyzer/mappings.js')).applyBuiltins(); if (n) console.log(JSON.stringify({ level: 'info', msg: `settled ${n} event names with built-in mappings` })); }
  catch (e) { console.log(JSON.stringify({ level: 'warn', msg: `built-in mappings: ${e.message}` })); }
  const srv = createApp().listen(config.port, '0.0.0.0', () => console.log(JSON.stringify({ level: 'info', msg: `listening on :${config.port}` })));
  const stop = () => srv.close(async () => { await closePool(); process.exit(0); });
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
