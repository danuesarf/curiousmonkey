// Light and dark themes. The dark theme is how every colour in the code is written. The light theme maps each
// colour on the fly: grounds and ink swap lightness, accents keep their hue and are darkened just enough to read on
// a light ground. The variables in app.css are tuned by hand; this covers the hundreds of literal colours in the
// drawings (Space, Radar, Track) and the few left in the stylesheet, so both themes stay one design.

const KEY = 'cm-theme';
let current = 'dark';
try { current = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'; } catch { /* not in a browser (tests) */ }

export const theme = () => current;

// ---------------------------------------------------------------- colour maths (DOM-free, unit tested)
const lin = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const gam = (c) => (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055);
function toOklab([r, g, b]) {
  const R = lin(r / 255), G = lin(g / 255), B = lin(b / 255);
  const l = Math.cbrt(0.4122214708 * R + 0.5363325363 * G + 0.0514459929 * B);
  const m = Math.cbrt(0.2119034982 * R + 0.6806995451 * G + 0.1073969566 * B);
  const s = Math.cbrt(0.0883024619 * R + 0.2817188376 * G + 0.6299787005 * B);
  return [0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s, 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s, 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s];
}
function fromOklab([L, a, b]) {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3, m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3, s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s, -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s, -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s];
}
const inGamut = (rgb) => rgb.every((c) => c >= -0.0005 && c <= 1.0005);
const clamp = (x, a, b) => Math.min(b, Math.max(a, x));
const smooth = (x, a, b) => { const t = clamp((x - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); };

/** The light-theme counterpart of one dark-theme colour, as [r, g, b] 0–255. */
export function lightRgb(rgb) {
  const [L, a, b] = toOklab(rgb);
  let C = Math.hypot(a, b), h = Math.atan2(b, a);
  // greys get the theme's faint mint so white strokes become green-black ink, not grey
  if (C < 0.012) { C = 0.012; h = 2.75; }
  // banana and other yellows turn to gold: yellow at a readable lightness is olive
  const deg = (h * 180) / Math.PI;
  if (deg > 80 && deg < 115 && C > 0.08) h = ((deg - 8 * smooth(C, 0.08, 0.15)) * Math.PI) / 180;
  // grounds and ink: the night-sky ground (L ≈ 0.15) becomes a pale mint paper (≈ 0.975), the pale ink (≈ 0.93) a deep green-black (≈ 0.24)
  const flip = clamp(1.12 - 0.94 * L, 0.16, 0.985);
  // accents: keep them coloured, but never brighter than reads on paper; dark accent grounds become pale tints
  const accent = L > 0.5 ? clamp(0.3 + 0.36 * L, 0.42, 0.64) : flip;
  const w = smooth(C, 0.05, 0.13);
  const L2 = flip + (accent - flip) * w;
  // pale tints lose some colour so the page stays calm; accents keep theirs
  let C2 = L2 > 0.85 ? C * (0.45 + 0.4 * w) : C * (1 + 0.15 * w);
  let out;
  for (let i = 0; i < 24; i++) { out = fromOklab([L2, C2 * Math.cos(h), C2 * Math.sin(h)]); if (inGamut(out)) break; C2 *= 0.9; }
  return out.map((c) => Math.round(clamp(gam(clamp(c, 0, 1)), 0, 1) * 255));
}

const HEX = /(?<!url\()#([0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{3,4})\b/gi;
const RGB = /rgba?\(\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\s*(?:,\s*([\d.]+%?)\s*)?\)/gi;
const NAMED = /(?<![\w-])(white|black)(?![\w-])/gi;
const hex2 = (n) => n.toString(16).padStart(2, '0');
const cache = new Map();

/** Every colour in a CSS value or SVG attribute, mapped to the light theme. Anything else passes through. */
export function lighten(value) {
  if (typeof value !== 'string' || !value) return value;
  let v = cache.get(value);
  if (v !== undefined) return v;
  v = value.replace(HEX, (m, x) => {
    if (x.length <= 4) x = [...x].map((c) => c + c).join('');
    const rgb = lightRgb([0, 2, 4].map((i) => parseInt(x.slice(i, i + 2), 16)));
    return `#${rgb.map(hex2).join('')}${x.length === 8 ? x.slice(6) : ''}`;
  }).replace(RGB, (m, r, g, b, al) => {
    const [R, G, B] = lightRgb([r, g, b].map(Number));
    return al == null ? `rgb(${R},${G},${B})` : `rgba(${R},${G},${B},${al})`;
  }).replace(NAMED, (m) => {
    // only where the whole token is the colour, not inside a word like `white-space`
    const [R, G, B] = lightRgb(m.toLowerCase() === 'white' ? [255, 255, 255] : [0, 0, 0]);
    return `#${[R, G, B].map(hex2).join('')}`;
  });
  if (cache.size > 5000) cache.clear();
  cache.set(value, v);
  return v;
}

/** What drawing code should use: the colour as written in the dark theme, or its light counterpart. */
export const paint = (value) => (current === 'light' ? lighten(value) : value);

// SVG attributes that carry a colour
export const COLOUR_ATTRS = new Set(['fill', 'stroke', 'stop-color', 'color', 'flood-color', 'lighting-color']);

// ---------------------------------------------------------------- the stylesheet
// Literal colours left in app.css are rewritten in place; the originals are kept so switching back is exact.
// Custom properties are skipped: the light values for those are written by hand in app.css.
let saved = null;
const COLOURISH = /(?<!url\()#[0-9a-f]{3,8}\b|rgba?\(|(?<![\w-])(white|black)(?![\w-])/i;
function eachStyle(rules, fn) {
  for (const r of rules) {
    if (r.style) fn(r.style);
    if (r.cssRules) eachStyle(r.cssRules, fn);
  }
}
function restyle() {
  if (!saved) {
    saved = [];
    for (const sheet of document.styleSheets) {
      let rules; try { rules = sheet.cssRules; } catch { continue; }
      eachStyle(rules, (st) => {
        for (let i = 0; i < st.length; i++) {
          const p = st[i];
          if (p.startsWith('--')) continue;
          const v = st.getPropertyValue(p);
          if (COLOURISH.test(v)) saved.push([st, p, v, st.getPropertyPriority(p)]);
        }
      });
    }
  }
  for (const [st, p, v, pr] of saved) st.setProperty(p, current === 'light' ? lighten(v) : v, pr);
}

const listeners = new Set();
export const onTheme = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };

/** Switch theme, remember it in this browser, and let the page redraw. */
export function setTheme(t) {
  current = t === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = current;
  try { localStorage.setItem(KEY, current); } catch { /* private mode: it lasts until the tab closes */ }
  restyle();
  for (const fn of listeners) fn(current);
}

/** Called once at start: bring the stylesheet in line with the theme theme-boot.js already set. */
export function initTheme() { if (current === 'light') restyle(); }
