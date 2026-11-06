import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { globMatch } from './wildcard.js';

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), 'catalog.json');
const raw = JSON.parse(fs.readFileSync(file, 'utf8'));

const LEVELS = { R: 'Read', L: 'List', W: 'Write', P: 'Permissions', T: 'Tagging' };

// service(lowercase) -> Map(actionLower -> { name, level, wildcardOnly, hasResource })
const services = new Map();
for (const [svc, def] of Object.entries(raw.services)) {
  const m = new Map();
  for (const [name, code] of Object.entries(def.a)) {
    m.set(name.toLowerCase(), {
      name,
      level: LEVELS[code[0]] || 'Write',
      wildcardOnly: code[1] === '1',
      hasResource: code[2] === '1',
    });
  }
  services.set(svc.toLowerCase(), { prefix: svc, actions: m });
}

export const catalogInfo = { dataVersion: raw.dataVersion, services: services.size };

export const hasService = (svc) => services.has(svc.toLowerCase());
export const servicePrefixes = () => [...services.values()].map((s) => s.prefix);

const splitAction = (a) => {
  const i = a.indexOf(':');
  return i < 0 ? [a, ''] : [a.slice(0, i), a.slice(i + 1)];
};

/** Metadata for one concrete action, or null when the catalog does not know it. */
export function actionInfo(action) {
  const [svc, name] = splitAction(action);
  const s = services.get(svc.toLowerCase());
  const a = s?.actions.get(name.toLowerCase());
  return a ? { action: `${s.prefix}:${a.name}`, service: s.prefix, ...a } : null;
}

export const accessLevel = (action) => actionInfo(action)?.level ?? null;

/** Expand a (possibly wildcarded) action pattern into every concrete action it grants. */
export function expandAction(pattern) {
  if (pattern === '*') {
    const out = [];
    for (const s of services.values()) for (const a of s.actions.values()) out.push(`${s.prefix}:${a.name}`);
    return out;
  }
  const [svcPat, namePat] = splitAction(pattern);
  const out = [];
  for (const s of services.values()) {
    if (!globMatch(svcPat, s.prefix, { ci: true })) continue;
    for (const a of s.actions.values()) {
      if (globMatch(namePat, a.name, { ci: true })) out.push(`${s.prefix}:${a.name}`);
    }
  }
  return out;
}

/** All actions of a service, concrete names. */
export function serviceActions(svc) {
  const s = services.get(svc.toLowerCase());
  return s ? [...s.actions.values()].map((a) => `${s.prefix}:${a.name}`) : [];
}

/** Canonical casing for an action seen in an event (iam:getrole -> iam:GetRole), or the input unchanged. */
export const canonicalAction = (action) => actionInfo(action)?.action ?? action;
