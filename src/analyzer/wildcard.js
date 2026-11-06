// IAM-style glob helpers. '*' matches any run of characters, '?' matches exactly one.
// Action names and ARNs are compared case-insensitively where the caller asks for it.

export function globMatch(pattern, value, { ci = false } = {}) {
  const p = ci ? pattern.toLowerCase() : pattern;
  const s = ci ? value.toLowerCase() : value;
  let pi = 0, si = 0, star = -1, mark = 0;
  while (si < s.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === s[si])) { pi++; si++; }
    else if (pi < p.length && p[pi] === '*') { star = pi++; mark = si; }
    else if (star !== -1) { pi = star + 1; si = ++mark; }
    else return false;
  }
  while (pi < p.length && p[pi] === '*') pi++;
  return pi === p.length;
}

export const hasWildcard = (s) => /[*?]/.test(s);

/**
 * Is every string matched by glob `a` also matched by glob `b`?
 * Sound: a `true` answer is always right. It may answer `false` for some exotic
 * pairs that are actually contained, which makes the "no new access" check stricter, never looser.
 */
export function isSubsetGlob(a, b, { ci = true } = {}) {
  if (ci) { a = a.toLowerCase(); b = b.toLowerCase(); }
  const memo = new Map();
  const f = (i, j) => {
    const key = i * (b.length + 1) + j;
    if (memo.has(key)) return memo.get(key);
    memo.set(key, false); // guards against cycles; every transition advances i or j
    let r;
    if (i === a.length) {
      r = true;
      for (let k = j; k < b.length; k++) if (b[k] !== '*') { r = false; break; }
    } else if (a[i] === '*') {
      if (j === b.length) r = false;
      else if (b[j] === '*') r = f(i, j + 1) || f(i + 1, j);
      else r = false; // a can produce anything here, b needs a specific character
    } else if (j === b.length) {
      r = false;
    } else if (b[j] === '*') {
      r = f(i, j + 1) || f(i + 1, j);
    } else if (b[j] === '?') {
      r = f(i + 1, j + 1); // one character of a (literal or '?') is always one character
    } else if (a[i] === '?') {
      r = false; // a allows any character, b wants exactly one
    } else {
      r = a[i] === b[j] && f(i + 1, j + 1);
    }
    memo.set(key, r);
    return r;
  };
  return f(0, 0);
}

/** True when `a` is covered by at least one pattern in `list`. */
export const coveredByAny = (a, list, opts) => list.some((b) => isSubsetGlob(a, b, opts));

/** Does this pattern match everything? ("*", "**", ...) */
export const isMatchAll = (s) => /^\*+$/.test(s);
