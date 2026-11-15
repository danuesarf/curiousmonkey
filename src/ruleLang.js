// The rule language of Manage policy. A rule is terms joined by AND, OR and NOT, grouped with brackets:
//   (environment = production OR environment = staging) AND kind = role AND idle > 90 AND policy != ReadOnly*
// A term is `key operator value`: = (or the older :), !=, >, >=, <, <=. A value may be quoted, may hold * as a wildcard,
// and may be a comma list (any of them; with != none of them). Terms side by side mean AND; a leading - means NOT.
// A bare word is searched as text. This file only reads the rule into a tree; what a key means is the caller's.

const OPS = ['!=', '>=', '<=', '=', ':', '>', '<'];
const isSpace = (ch) => ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';

function tokens(src) {
  const out = [], errors = [];
  let i = 0;
  const skip = () => { while (i < src.length && isSpace(src[i])) i++; };
  const quoted = () => { const end = src.indexOf('"', i + 1); if (end < 0) { errors.push('A quote is not closed.'); const v = src.slice(i + 1); i = src.length; return v; } const v = src.slice(i + 1, end); i = end + 1; return v; };
  const bare = () => { const s = i; while (i < src.length && !isSpace(src[i]) && src[i] !== ')' && src[i] !== '(' && src[i] !== ',') i++; return src.slice(s, i); };
  // a value: one or more parts separated by commas, each quoted or not
  const value = () => {
    const parts = [];
    for (;;) {
      parts.push(src[i] === '"' ? quoted() : bare());
      if (src[i] === ',') { i++; continue; }
      break;
    }
    return parts.map((p) => p.trim()).filter((p) => p !== '');
  };
  while (i < src.length) {
    skip();
    if (i >= src.length) break;
    const ch = src[i];
    if (ch === '(' || ch === ')') { out.push({ t: ch }); i++; continue; }
    if (ch === '"') { out.push({ t: 'text', value: quoted() }); continue; }
    let neg = false;
    if (ch === '-' && /[A-Za-z_"(]/.test(src[i + 1] || '')) { neg = true; i++; if (src[i] === '(') { out.push({ t: 'not' }); continue; } if (src[i] === '"') { out.push({ t: 'not' }, { t: 'text', value: quoted() }); continue; } }
    const id = /^[A-Za-z_][\w.-]*/.exec(src.slice(i))?.[0];
    if (id) {
      const save = i; i += id.length;
      const afterId = i; skip();
      const op = OPS.find((o) => src.startsWith(o, i));
      if (op) {
        i += op.length; skip();
        // the older form: key:>90
        let real = op;
        if (op === ':') { const cmp = ['>=', '<=', '!=', '>', '<', '='].find((o) => src.startsWith(o, i)); if (cmp) { real = cmp; i += cmp.length; skip(); } }
        const values = i < src.length && src[i] !== ')' ? value() : [];
        if (!values.length) errors.push(`${id} ${real === ':' ? '=' : real} needs a value.`);
        if (neg) out.push({ t: 'not' });
        out.push({ t: 'term', key: id.toLowerCase(), op: real === ':' ? '=' : real, values });
        continue;
      }
      i = afterId;
      const up = id.toUpperCase();
      if (!neg && (up === 'AND' || up === 'OR' || up === 'NOT') && (i >= src.length || isSpace(src[i]) || src[i] === '(')) { out.push({ t: up.toLowerCase() }); continue; }
      i = save;
    }
    // a bare word, searched as text
    const s = i; while (i < src.length && !isSpace(src[i]) && src[i] !== ')' && src[i] !== '(') i++;
    if (i === s) { i++; continue; }
    if (neg) out.push({ t: 'not' });
    out.push({ t: 'text', value: src.slice(s, i) });
  }
  return { out, errors };
}

// Limits: a rule is typed by a person and run against the database, so it is kept small enough to be cheap whatever it says.
export const LIMITS = { length: 2000, terms: 60, depth: 12, values: 50, valueLength: 200, wildcards: 6 };

/** Read a rule. Returns { ast, errors }: ast is null for an empty rule or one that cannot be read. */
export function parseRule(text) {
  const src = String(text || '');
  if (src.length > LIMITS.length) return { ast: null, errors: [`A rule can be ${LIMITS.length} characters at most; this one is ${src.length}.`] };
  const { out: toks, errors } = tokens(src);
  const leafCount = toks.filter((t) => t.t === 'term' || t.t === 'text').length;
  if (leafCount > LIMITS.terms) return { ast: null, errors: [`A rule can have ${LIMITS.terms} terms at most; this one has ${leafCount}.`] };
  for (const t of toks) {
    const vs = t.t === 'term' ? t.values : t.t === 'text' ? [t.value] : [];
    if (vs.length > LIMITS.values) errors.push(`${t.key}: ${LIMITS.values} values at most in one list.`);
    for (const v of vs) {
      if (v.length > LIMITS.valueLength) errors.push(`A value can be ${LIMITS.valueLength} characters at most.`);
      if ((v.match(/[*?]/g) || []).length > LIMITS.wildcards) errors.push(`A value can hold ${LIMITS.wildcards} wildcards at most: "${v.slice(0, 40)}".`);
      if (/[\u0000-\u001f]/.test(v)) errors.push('A value cannot hold control characters.');
    }
  }
  if (errors.length) return { ast: null, errors: [...new Set(errors)] };
  let depth = 0;
  let p = 0;
  const peek = () => toks[p];
  const primary = () => {
    const t = toks[p];
    if (!t) { errors.push('The rule ends where a term was expected.'); return null; }
    if (t.t === '(') {
      p++;
      if (++depth > LIMITS.depth) { errors.push(`Brackets can be nested ${LIMITS.depth} deep at most.`); return null; }
      const e = or();
      depth--;
      if (peek()?.t === ')') p++; else errors.push('A bracket is not closed.');
      return e;
    }
    if (t.t === 'term') { p++; return { t: 'term', key: t.key, op: t.op, values: t.values }; }
    if (t.t === 'text') { p++; return { t: 'text', value: t.value }; }
    errors.push(t.t === ')' ? 'A closing bracket has no opening one.' : `"${t.t.toUpperCase()}" is where a term was expected.`);
    p++;
    return null;
  };
  const not = () => {
    let n = 0;
    while (peek()?.t === 'not') { p++; n++; }                  // NOT NOT x is x: counted, not nested
    const kid = primary();
    return kid && n % 2 ? { t: 'not', kid } : kid;
  };
  const and = () => {
    const kids = [not()];
    for (;;) {
      const t = peek();
      if (!t || t.t === 'or' || t.t === ')') break;
      if (t.t === 'and') { p++; if (!peek() || peek().t === ')') { errors.push('AND needs a term after it.'); break; } }
      kids.push(not());
    }
    const k = kids.filter(Boolean);
    return k.length > 1 ? { t: 'and', kids: k } : k[0] || null;
  };
  function or() {
    const kids = [and()];
    while (peek()?.t === 'or') { p++; if (!peek() || peek().t === ')') { errors.push('OR needs a term after it.'); break; } kids.push(and()); }
    const k = kids.filter(Boolean);
    return k.length > 1 ? { t: 'or', kids: k } : k[0] || null;
  }
  if (!toks.length) return { ast: null, errors };
  const ast = or();
  if (p < toks.length && !errors.length) errors.push(toks[p].t === ')' ? 'A closing bracket has no opening one.' : 'The rule could not be read to its end.');
  return { ast: errors.length ? null : ast, errors: [...new Set(errors)] };
}

/** Every term and text leaf of a rule. */
export function leaves(ast, out = []) {
  if (!ast) return out;
  if (ast.t === 'term' || ast.t === 'text') out.push(ast);
  else if (ast.t === 'not') leaves(ast.kid, out);
  else for (const k of ast.kids) leaves(k, out);
  return out;
}

/** Walk a rule with a function per leaf: `leaf(node)` returns a boolean; and/or/not are worked out here. */
export function evaluate(ast, leaf) {
  if (!ast) return false;
  if (ast.t === 'and') return ast.kids.every((k) => evaluate(k, leaf));
  if (ast.t === 'or') return ast.kids.some((k) => evaluate(k, leaf));
  if (ast.t === 'not') return !evaluate(ast.kid, leaf);
  return leaf(ast);
}

/** A value with * and ? as a test on strings: the whole string when it has a wildcard (or `exact`), else "contains". */
export function globTest(v, { exact = false } = {}) {
  const esc = String(v).toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&');
  if (/[*?]/.test(v)) { const re = new RegExp(`^${esc.replace(/\*/g, '.*').replace(/\?/g, '.')}$`); return (s) => re.test(String(s ?? '').toLowerCase()); }
  const needle = String(v).toLowerCase();
  return exact ? (s) => String(s ?? '').toLowerCase() === needle : (s) => String(s ?? '').toLowerCase().includes(needle);
}

export function closest(word, list) {
  const d = (a, b) => { const m = Array.from({ length: a.length + 1 }, (_, i) => [i]); for (let j = 1; j <= b.length; j++) m[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) m[i][j] = Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return m[a.length][b.length]; };
  const best = list.map((k) => [k, d(word, k)]).sort((x, y) => x[1] - y[1])[0];
  return best && best[1] <= 2 ? best[0] : null;
}
