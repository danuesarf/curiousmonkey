// Radar. Two views, one dish:
//   Estate  — each contact is an AWS account. Distance = share of permissions never called; size = excess permissions;
//             trail = where it was 7 and 30 days ago; brightness = activity in the last 24 h; pings = changes that matter.
//   Account — the same for one account's roles, sectored by kind.
import { h, svg, get, getCached, post, num, ago, loadEnvironments, envName, envs, paint, whoControl, whoOf, whoQs, COLOR, CHANGE_KIND, r1, syncUrl, wallMode } from '../lib.js';
import { go, changeRow, refreshBell } from '../main.js';

const CX = 400, CY = 400;
// drawn text is enlarged when the dish is shown small, so it never renders under about 11 px (set before each draw)
let FZ = 1;
const textScale = (el) => { const r = el.getBoundingClientRect(), k = Math.min(r.width / 1020, r.height / 800); FZ = k > 0 ? Math.max(1, Math.min(1.8, 11 / (10 * k))) : 1; };
// redraw when the dish changes size (a panel opens below, the window is resized)
const onResize = (el, fn) => { let last = ''; new ResizeObserver(() => { const r = el.getBoundingClientRect(), s = `${Math.round(r.width)}x${Math.round(r.height)}`; if (r.width && s !== last) { last = s; fn(); } }).observe(el); };
const SEV = COLOR;
const KIND_LABEL = { custom: 'Custom', 'identity-center': 'Identity Center', 'service-linked': 'Service-linked', 'iam-user': 'IAM users' };
const ui = { group: 'env', chip: null };          // remembered while you move between views
const P = (deg, r) => { const a = ((deg - 90) * Math.PI) / 180; return [r1(CX + Math.cos(a) * r), r1(CY + Math.sin(a) * r)]; };
const RAD = (s) => 56 + Math.max(0, Math.min(1, s ?? 0)) * 258;
const still = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const kfmt = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}k` : num(Math.round(n)));
const shape = (kind, x, y, s) => kind === 'identity-center' ? `M${r1(x - s)} ${r1(y - s)}h${r1(2 * s)}v${r1(2 * s)}h${r1(-2 * s)}Z`
  : kind === 'service-linked' ? `M${x} ${r1(y - s * 1.3)}L${r1(x + s * 1.3)} ${y}L${x} ${r1(y + s * 1.3)}L${r1(x - s * 1.3)} ${y}Z`
  : `M${r1(x - s)} ${y}a${s} ${s} 0 1 0 ${r1(2 * s)} 0a${s} ${s} 0 1 0 ${r1(-2 * s)} 0Z`;
const drift = (now, past) => (now == null || past == null ? null : now - past);
const headColor = (d) => (d == null ? '#7e978a' : d > 0.04 ? '#f0b45a' : d < -0.04 ? '#6fe3b0' : '#7e978a');
const headText = (d) => (d == null ? '· no trail yet' : Math.abs(d) < 0.01 ? '· flat' : `${d > 0 ? '▲' : '▼'} ${Math.abs(d * 100).toFixed(1)} pts`);
const short = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));
const pl = (n, w) => `${num(n)} ${w}${n === 1 ? '' : 's'}`;
// a trend too small to show reads as flat, never as -0.0%
const pct = (t, sign = false) => (Math.abs(t) < 0.0005 ? 'flat' : `${sign ? (t > 0 ? '+' : '−') : (t > 0 ? '▲ ' : '▼ ')}${Math.abs(t * 100).toFixed(1)}%`);
const riskClass = (r) => ({ High: 'b-high', Medium: 'b-medium', Low: 'b-low' })[r] || 'b-neutral';

export async function radarPage(ctx) {
  await loadEnvironments();
  const view = ctx.params.get('view') || 'estate';
  const tabs = h('div', { class: 'rtabs', role: 'tablist', 'aria-label': 'Radar view' },
    [['estate', 'Estate'], ['account', 'Account']].map(([k, label]) => h('button', { role: 'tab', 'aria-selected': String(view === k),
      onClick: () => go(k === 'estate' ? `#/${whoQs(whoOf(ctx.params))}` : `#/?view=account${ctx.params.get('account') ? `&account=${ctx.params.get('account')}` : ''}${whoQs(whoOf(ctx.params), '&')}`) }, label)));
  const shell = { left: h('aside', { class: 'left' }), scene: h('div', { class: 'scene' }), right: h('aside', { class: 'right' }) };
  const who = whoOf(ctx.params);
  const withWho = (k) => { const p = new URLSearchParams(ctx.params); if (k === 'all') p.delete('who'); else p.set('who', k); go(`#/?${p}`); };
  shell.left.append(tabs, whoControl(who, withWho));
  ctx.who = who;
  const page = h('div', { class: 'stack radar-page radar3', style: 'gap:0' }, h('div', { class: 'scene-layout radar-layout' }, shell.left, shell.scene, shell.right));
  if (view === 'account') await accountView(ctx, shell);
  else await estateView(ctx, shell);
  return page;
}

// ---------------------------------------------------------------- shared drawing
function base(kids, rings, ringLabels) {
  kids.push(svg('defs', null,
    svg('filter', { id: 'g3', x: '-80%', y: '-80%', width: '260%', height: '260%' }, svg('feGaussianBlur', { stdDeviation: 2.6, result: 'b' }),
      svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' })))));
  kids.push(svg('circle', { cx: CX, cy: CY, r: 324, fill: '#051209', stroke: '#1f4a35' }));
  for (const [r, fill, dash] of rings) kids.push(svg('circle', { cx: CX, cy: CY, r: r1(r), fill, stroke: '#1a4231', 'stroke-dasharray': dash }));
  return () => {     // call after sectors: labels go on top of them
    for (const [t, rr, color] of ringLabels) {
      const y = r1(CY - rr + 4 * FZ), bw = (t.length * 6.6 + 10) * FZ;
      kids.push(svg('rect', { x: r1(CX - bw / 2), y: r1(y - 11.5 * FZ), width: r1(bw), height: r1(16 * FZ), fill: '#030d08', opacity: 0.85, 'pointer-events': 'none' }),
        svg('text', { x: CX, y, 'text-anchor': 'middle', fill: color, 'font-family': 'Geist Mono, monospace', 'font-size': r1(10 * FZ), 'letter-spacing': 1.2, 'pointer-events': 'none' }, t));
    }
  };
}
const ZONE_RINGS = [[RAD(1) + 8, '#130f0b', null], [RAD(0.995), '#0b1c11', null], [RAD(0.75), '#081a10', '3 5'], [RAD(0.25), '#06160e', '3 5']];
const ZONE_LABELS = [['DEAD', RAD(1) + 6, '#ffb3aa'], ['BLOATED · >75%', RAD(0.87), '#ffd89a'], ['LOOSE', RAD(0.5), '#c9d98a'], ['TIGHT', RAD(0.12), '#9fe8c4']];

function sectors(groups, total, gap) {
  const span = 360 - gap * groups.length; let a0 = 0;
  return groups.map((g) => { const w = (span * g.weight) / Math.max(total, 1); const s = { ...g, a0: a0 + gap / 2, a1: a0 + gap / 2 + w }; a0 += w + gap; return s; });
}
function drawSectors(kids, secs, sub, onClick) {
  const boxes = [];
  for (const s of secs) {
    const [ex0, ey0] = P(s.a0 - 2, 56), [ex1, ey1] = P(s.a0 - 2, 324), [ax0, ay0] = P(s.a0, 324), [ax1, ay1] = P(s.a1, 324);
    if (secs.length > 1) kids.push(svg('path', { d: `M${ex0} ${ey0} L${ex1} ${ey1}`, stroke: '#2a5c45', 'stroke-width': 1.2 }));
    kids.push(svg('path', { d: `M${ax0} ${ay0} A324 324 0 ${s.a1 - s.a0 > 180 ? 1 : 0} 1 ${ax1} ${ay1}`, fill: 'none', stroke: s.color || '#2f6e52', 'stroke-width': 3 }, svg('title', null, `${s.name} · ${sub(s)}`)));
    if (s.a1 - s.a0 < 10) continue;
    const mid = (s.a0 + s.a1) / 2; const [lx, lyr] = P(mid, 344 + 6 * (FZ - 1)); const ly = r1(lyr + (lyr < CY ? -8 - 12 * (FZ - 1) : 6));
    const anchor = Math.abs(lx - CX) < 40 ? 'middle' : lx > CX ? 'start' : 'end';
    const t2 = sub(s); const fit = (w) => (anchor === 'start' ? Math.min(lx, 906 - w) : anchor === 'end' ? Math.max(lx, -106 + w) : lx);
    const bw = Math.max(s.name.length * 7.3, t2.length * 5.6) * FZ, bx = fit(bw), x0 = anchor === 'start' ? bx : anchor === 'end' ? bx - bw : bx - bw / 2;
    boxes.push([x0, ly - 12 * FZ, x0 + bw, ly + 18 * FZ]);
    kids.push(svg('g', onClick ? { style: 'cursor:pointer', onClick: (e) => { e.stopPropagation(); onClick(s); } } : null,
      svg('text', { x: r1(fit(s.name.length * 7.3 * FZ)), y: ly, 'text-anchor': anchor, fill: '#e3efe8', 'font-family': 'Geist Mono, monospace', 'font-size': r1(12 * FZ) }, s.name),
      svg('text', { x: r1(fit(t2.length * 5.6 * FZ)), y: r1(ly + 14 * FZ), 'text-anchor': anchor, fill: '#7e978a', 'font-size': r1(11 * FZ) }, t2)));
  }
  return boxes;
}
function contact(kids, c) {
  // c: { d, x, y, fill, stroke, base, act, ang, title, sel, isNew, onClick }
  const g = svg('g', { style: 'cursor:pointer', onClick: (e) => { e.stopPropagation(); c.onClick?.(); } }, svg('title', null, c.title),
    // what can be clicked is never smaller than about 12 px on screen, however small the contact
    svg('circle', { cx: c.x, cy: c.y, r: r1(Math.max(c.s + 3, 8 * FZ)), fill: '#000', opacity: 0 }));
  // brighter = busier in the last 24 h
  const body = svg('path', { d: c.d, fill: c.fill, stroke: c.stroke || null, 'stroke-width': c.stroke ? 1.4 : null, opacity: r1(Math.min(1, c.base + (c.act ?? 0) * 0.6)) });
  g.append(body);
  if (c.isNew) g.append(svg('circle', { cx: c.x, cy: c.y, r: r1(c.s + 4), fill: 'none', stroke: '#8ec5ff', 'stroke-width': 1.2, 'stroke-dasharray': '2 2' }));
  if (c.sel) g.append(svg('circle', { cx: c.x, cy: c.y, r: r1(c.s + 6), fill: 'none', stroke: '#f6e016', 'stroke-width': 1.5 }));
  kids.push(g);
}
function ping(kids, x, y, r, color) {
  // a change that matters: a ring that pulses gently, so it can be found without anything sweeping the screen
  const g = svg('g', { 'pointer-events': 'none' }, svg('circle', { cx: x, cy: y, r: r1(r), fill: 'none', stroke: color, 'stroke-width': 1.4 }));
  if (!still()) g.append(svg('circle', { cx: x, cy: y, r: r1(r), fill: 'none', stroke: color, 'stroke-width': 1.4 },
    svg('animate', { attributeName: 'r', values: `${r1(r)};${r1(r + 9)}`, dur: '2.4s', repeatCount: 'indefinite' }),
    svg('animate', { attributeName: 'opacity', values: '0.8;0', dur: '2.4s', repeatCount: 'indefinite' })));
  kids.push(g);
}
function trail(kids, ang, from, mid, to, d) {
  if (from == null || Math.abs(d) < 0.015) return;
  const [ox, oy] = P(ang, RAD(from)), [mx, my] = P(ang, RAD(mid ?? from)), [x, y] = P(ang, RAD(to));
  const color = d > 0 ? '#f0b45a' : '#6fe3b0', strong = Math.abs(d) > 0.06;
  kids.push(svg('path', { d: `M${ox} ${oy} L${mx} ${my} L${x} ${y}`, stroke: color, 'stroke-width': strong ? 2.4 : 1.4, 'stroke-linecap': 'round', opacity: strong ? 0.95 : 0.5, fill: 'none', 'pointer-events': 'none' }),
    svg('circle', { cx: ox, cy: oy, r: 1.6, fill: color, opacity: strong ? 0.95 : 0.5, 'pointer-events': 'none' }));
}
function tags(kids, cands, max, extraBoxes = []) {
  const placed = [[CX - 60 * FZ, CY - 50 * FZ, CX + 60 * FZ, CY + 50 * FZ], ...extraBoxes]; let n = 0;
  for (const c of cands) {
    if (n >= max) break;
    const bw = (c.text.length * 6.6 + 10) * FZ, bh = 18 * FZ;
    for (const push of [16, 32, -20, 48]) {
      const [tx, ty] = P(c.ang, c.rad + push * FZ); const left = tx < CX; const bx = left ? tx - bw : tx, by = ty - bh / 2;
      const box = [bx, by, bx + bw, by + bh];
      if (box[0] < -100 || box[2] > 900 || box[1] < 4 || box[3] > 796) continue;
      if (placed.some((q) => box[0] < q[2] + 2 && box[2] > q[0] - 2 && box[1] < q[3] + 2 && box[3] > q[1] - 2)) continue;
      placed.push(box); n++;
      kids.push(svg('g', { 'pointer-events': 'none' },
        svg('path', { d: `M${c.x} ${c.y} L${r1(left ? bx + bw : bx)} ${r1(by + bh / 2)}`, stroke: c.color, 'stroke-width': 1, opacity: 0.7 }),
        svg('rect', { x: r1(bx), y: r1(by), width: r1(bw), height: r1(bh), fill: '#030d08', stroke: c.color, 'stroke-width': 1 }),
        svg('text', { x: r1(bx + 5 * FZ), y: r1(by + 13 * FZ), fill: c.color, 'font-family': 'Geist Mono, monospace', 'font-size': r1(10.5 * FZ) }, c.text)));
      break;
    }
  }
}
function dial(kids, top, value, color, trend, trendColor) {
  const k = Math.min(FZ, 1.25);    // the dial grows less than the text, so it does not cover the dish
  kids.push(svg('circle', { cx: CX, cy: CY, r: r1(46 * k), fill: '#030d08', stroke: '#2a5c45' }),
    svg('text', { x: CX, y: r1(CY - 11 * k), 'text-anchor': 'middle', fill: '#7e978a', 'font-family': 'Geist Mono, monospace', 'font-size': r1(8.5 * FZ), 'letter-spacing': 1 }, top),
    svg('text', { x: CX, y: r1(CY + 8 * k), 'text-anchor': 'middle', fill: color, 'font-size': r1(19 * k), 'font-weight': 500 }, value),
    svg('text', { x: CX, y: r1(CY + 23 * k), 'text-anchor': 'middle', fill: trendColor, 'font-family': 'Geist Mono, monospace', 'font-size': r1(9.5 * FZ) }, trend));
}
const stage = (label) => svg('svg', { class: 'stage', viewBox: '-110 0 1020 800', preserveAspectRatio: 'xMidYMid meet', role: 'img', 'aria-label': label });
const hudEl = (a, b, c) => h('div', { class: 'hud' }, h('div', { class: 'hot' }, `● ${a}`), h('div', null, b), h('div', null, c));
function legend(items) {
  return h('div', { class: 'legend' }, items.map(([sw, t]) => { const s = h('span', { 'aria-hidden': 'true' }); s.style.cssText = paint(sw); return h('span', null, s, t); }));
}
/** The never-called share day by day (an account's median role, or one role), on a scale fitted to the data. */
function trailEl(qs, color) {
  const box = h('div', { class: 'stack', style: 'gap:2px;min-height:58px' }, h('p', { class: 'tiny muted' }, 'Loading…'));
  getCached(`/radar/trail?${qs}`, 300_000).then((t) => {
    const pts = t.points.filter((x) => x.v != null);
    if (pts.length < 2) { box.replaceChildren(h('p', { class: 'tiny muted' }, 'A line appears once there are two days of snapshots.')); return; }
    const vs = pts.map((x) => x.v), lo0 = Math.min(...vs), hi0 = Math.max(...vs), mid = (lo0 + hi0) / 2, span = Math.max(0.04, hi0 - lo0) * 1.15;
    const lo = mid - span / 2, t0 = new Date(pts[0].day).getTime(), t1 = new Date(pts.at(-1).day).getTime() || t0 + 1;
    const xy = pts.map((x) => [r1(((new Date(x.day).getTime() - t0) / Math.max(1, t1 - t0)) * 296 + 2), r1(50 - ((x.v - lo) / span) * 46)]);
    const pc = (v) => `${Math.round(v * 1000) / 10}%`;
    box.replaceChildren(
      svg('svg', { viewBox: '0 0 300 54', style: 'width:100%;height:54px', role: 'img', 'aria-label': `Never-called share, ${pts.length} days: from ${pc(vs[0])} to ${pc(vs.at(-1))}` },
        svg('path', { d: 'M0 53 H300', stroke: '#143425' }), svg('polyline', { points: xy.map((q) => q.join(',')).join(' '), fill: 'none', stroke: color, 'stroke-width': 1.6 }),
        svg('circle', { cx: xy.at(-1)[0], cy: xy.at(-1)[1], r: 2.4, fill: color })),
      h('div', { class: 'row tiny muted', style: 'justify-content:space-between' }, h('span', null, `${pc(vs[0])} · ${pts.length} days ago`), h('span', null, `range ${pc(lo0)}–${pc(hi0)}`), h('span', null, `now ${pc(vs.at(-1))}`)));
  }).catch(() => box.replaceChildren(h('p', { class: 'tiny muted' }, 'Could not load the heading.')));
  return box;
}
/** The feed's range, from the address (?feed=1|7|30|90 days). */
const feedDays = (ctx) => ([1, 7, 30, 90].includes(Number(ctx.params.get('feed'))) ? Number(ctx.params.get('feed')) : 7);
const RANGE = { 1: 'last 24 hours', 7: 'last 7 days', 30: 'last 30 days', 90: 'last 90 days' };
/** The change feed: the same rows as the bell, for a range. Changing the range keeps the rest of the address. */
function feedSection(title, F, onPick) {
  const sel = h('select', { class: 'feed-range', 'aria-label': 'How far back' }, Object.entries(RANGE).map(([d, l]) => h('option', { value: d, selected: Number(d) === F.days }, l)));
  sel.addEventListener('change', () => { const [path, qs] = location.hash.split('?'); const p = new URLSearchParams(qs || ''); p.set('feed', sel.value); go(`${path || '#/'}?${p}`); });
  const n = F.items.filter((f) => f.unread).length;
  return h('section', { class: 'stack', style: 'gap:6px' },
    h('div', { class: 'row', style: 'justify-content:space-between;gap:8px' }, h('span', { class: 'eyebrow' }, `${title}${n ? ` · ${n} NEW` : ''}`), sel),
    F.items.length ? h('div', { class: 'stack', style: 'gap:6px' }, F.items.map((f) => changeRow(f, onPick)))
      : h('p', { class: 'tiny muted' }, `No changes in the ${RANGE[F.days]}. Changes are recorded once an account’s history is fully read, from one daily analysis to the next.`));
}

// ---------------------------------------------------------------- estate
async function estateView(ctx, shell) {
  ctx.setCrumbs('Radar', 'Estate');
  // replay: the estate as it was N days ago, from the daily snapshots (0 = now)
  let asOf = Math.max(0, Math.min(90, Math.floor(Number(ctx.params.get('asof')) || 0)));
  const estateUrl = () => `/radar/estate?${new URLSearchParams({ ...(ctx.who === 'all' ? {} : { who: ctx.who }), ...(asOf ? { asof: asOf } : {}) })}`;
  let [E, F] = await Promise.all([get(estateUrl()), get(`/changes?days=${feedDays(ctx)}`)]);
  // looking at the estate's feed counts as seeing it: the bell empties (this page still marks what was new)
  post('/changes/seen').then(refreshBell).catch(() => {});
  let accounts = E.accounts;
  if (!accounts.length) { shell.scene.append(h('div', { class: 'card empty', style: 'margin:40px' }, 'No accounts yet. ', h('a', { href: '#/accounts/new' }, 'Connect an AWS account'))); return; }
  let maxEx = 1, maxAct = 1;
  const prep = () => { for (const a of accounts) { a.d30 = drift(a.never, a.never30); a.d7 = drift(a.never, a.never7); } maxEx = Math.max(1, ...accounts.map((a) => a.excess)); maxAct = Math.max(1, ...accounts.map((a) => a.calls24h)); };
  prep();
  let sel = accounts.find((a) => a.id === ctx.params.get('sel')) || null;
  if (['env', 'ou'].includes(ctx.params.get('group'))) ui.group = ctx.params.get('group');
  if (ctx.params.has('chip') || ctx.params.has('sel')) ui.chip = ctx.params.get('chip') || null;
  const CHIPS = [['worse', 'Getting worse', '#f0b45a', (a) => (a.d30 ?? 0) > 0.04], ['better', 'Improving', '#6fe3b0', (a) => (a.d30 ?? 0) < -0.04],
    ['pinged', 'Has pings', '#ff5a4f', (a) => a.pings > 0], ['loading', 'Loading', '#f6e016', (a) => !a.complete]];
  const svgEl = stage('Estate radar: each contact is an AWS account. Distance is how much of its median role is never called; size is its excess permissions; trails show where it was 7 and 30 days ago.');
  const listEl = h('div', { class: 'rank-list' }), controls = h('div', { class: 'stack', style: 'gap:10px' });
  const hasOu = accounts.some((a) => a.ou);

  function draw() {
    textScale(svgEl);
    if (ui.chip && !CHIPS.some((c) => c[0] === ui.chip)) ui.chip = null;
    // what is shown goes in the address: reload and a copied link give the same view
    if (!ctx.inWindow) syncUrl({ who: ctx.who === 'all' ? null : ctx.who, feed: F.days === 7 ? null : F.days, asof: asOf || null, group: ui.group === 'env' ? null : ui.group, chip: ui.chip, sel: sel?.id });
    const cf = ui.chip ? CHIPS.find((c) => c[0] === ui.chip)[3] : null;
    const key = (a) => (ui.group === 'ou' ? a.ou || 'No OU set' : a.environment);
    const order = ui.group === 'ou' ? [...new Set(accounts.map(key))].sort() : [...new Set(accounts.map(key))].sort((x, y) => (envs().findIndex((e) => e.id === x) + 1 || 99) - (envs().findIndex((e) => e.id === y) + 1 || 99));
    const groups = order.map((k) => ({ id: k, name: k.toUpperCase(), list: accounts.filter((a) => key(a) === k) })).map((g) => ({ ...g, weight: g.list.length }));
    const secs = sectors(groups, accounts.length, 5);
    for (const s of secs) {
      const list = s.list.slice().sort((x, y) => x.name.localeCompare(y.name));
      list.forEach((a, i) => { a.ang = s.a0 + 1.5 + ((i + 0.5) / list.length) * (s.a1 - s.a0 - 3); a.rad = RAD(a.never); [a.x, a.y] = P(a.ang, a.rad); a.s = r1(3 + Math.sqrt(Math.max(0, a.excess) / maxEx) * 13); });
    }
    const kids = []; const top = base(kids, ZONE_RINGS, ZONE_LABELS);
    const secBoxes = drawSectors(kids, secs, (s) => `${pl(s.list.length, 'acct')} · ${pl(s.list.reduce((t, x) => t + x.roles, 0), 'role')}`);
    top();
    for (const a of accounts) if (!cf || cf(a)) trail(kids, a.ang, a.never30, a.never7, a.never, a.d30 ?? 0);
    for (const a of accounts) {
      if (a.absent) continue;        // replaying a day before its first snapshot: it was not on the radar yet
      const on = !cf || cf(a);
      contact(kids, { d: shape('custom', a.x, a.y, a.s), x: a.x, y: a.y, s: a.s, fill: !a.complete ? '#030d08' : a.high >= 8 ? '#ff8a7a' : '#6fe3b0', stroke: !a.complete ? '#f6e016' : null,
        base: a.absent ? 0.06 : on ? 0.45 : 0.1, act: on && !a.absent ? a.calls24h / maxAct : 0, ang: a.ang, sel: sel === a, isNew: a.isNew,
        title: `${a.name} · ${pl(a.roles, 'role')} · median role ${Math.round((a.never ?? 0) * 100)}% never called · ${headText(a.d30)} in 30 days${a.complete ? '' : ` · ${a.progress}% read`}`,
        onClick: () => { sel = a; draw(); card(); } });
    }
    for (const a of accounts) if (a.pings && (!cf || cf(a))) ping(kids, a.x, a.y, a.s + 4, SEV[a.pingSeverity] || SEV.info, a.ang);
    const cands = [];
    if (sel) cands.push({ ...sel, text: sel.name, color: '#f6e016' });
    for (const a of accounts.filter((x) => x.pings && (!cf || cf(x))).sort((x, y) => ['high', 'warn', 'info', 'good'].indexOf(x.pingSeverity) - ['high', 'warn', 'info', 'good'].indexOf(y.pingSeverity))) cands.push({ ...a, text: a.name, color: SEV[a.pingSeverity] });
    for (const a of accounts.filter((x) => (x.d30 ?? 0) > 0.04 && (!cf || cf(x))).sort((x, y) => y.d30 - x.d30).slice(0, 5)) cands.push({ ...a, text: `${a.name} ${headText(a.d30).replace(' pts', '')}`, color: '#f0b45a' });
    const seen = new Set(); tags(kids, cands.filter((c) => (seen.has(c.id) ? false : seen.add(c.id))), 12, secBoxes);
    const T = E.totals; const trend = T.excess30 ? (T.excessNowComparable - T.excess30) / T.excess30 : null;
    dial(kids, 'ESTATE EXCESS', kfmt(T.excess), '#f6e016', trend == null ? 'trend after 30 d' : `${pct(trend)} · 30 D`, trend == null || Math.abs(trend) < 0.0005 ? '#7e978a' : trend > 0 ? '#f0b45a' : '#6fe3b0');
    svgEl.replaceChildren(...kids);

    // left
    controls.replaceChildren(
      h('div', { class: 'row tiny muted', style: 'gap:8px' }, 'Sectors',
        [['env', 'Environment'], ['ou', 'OU']].map(([k, l]) => h('button', { class: 'chip', 'aria-pressed': String(ui.group === k), title: k === 'ou' && !hasOu ? 'Set an OU on each account (Accounts → Edit) to group by it' : null, onClick: () => { ui.group = k; draw(); } }, l))),
      h('div', { class: 'row', style: 'flex-wrap:wrap;gap:6px' }, CHIPS.map(([k, l, c, f]) => {
        const dot = h('span', { 'aria-hidden': 'true' }); dot.style.cssText = `width:7px;height:7px;border-radius:50%;background:${c};display:inline-block;margin-right:6px`;
        return h('button', { class: 'chip', 'aria-pressed': String(ui.chip === k), onClick: () => { ui.chip = ui.chip === k ? null : k; draw(); } }, dot, l, h('span', { class: 'mono tiny', style: 'opacity:.8' }, ` ${accounts.filter(f).length}`));
      })),
      h('div', { class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'eyebrow' }, ui.chip === 'worse' ? 'ACCOUNTS · WORST HEADING FIRST' : ui.chip === 'better' ? 'ACCOUNTS · MOST IMPROVED FIRST' : 'ACCOUNTS · MOST EXCESS FIRST'),
        h('span', { class: 'mono tiny muted' }, String(accounts.filter((a) => !cf || cf(a)).length))));
    const q = find.value.trim().toLowerCase();
    const listed = accounts.filter((a) => (!cf || cf(a)) && (!q || `${a.name} ${a.awsAccountId} ${a.ou || ''}`.toLowerCase().includes(q))).sort((x, y) => (ui.chip === 'better' ? (x.d30 ?? 0) - (y.d30 ?? 0) : ui.chip === 'worse' ? (y.d30 ?? 0) - (x.d30 ?? 0) : y.excess - x.excess));
    listEl.replaceChildren(...listed.map((a) => h('button', { class: 'rank-row', 'aria-pressed': String(sel === a), onClick: () => { sel = sel === a ? null : a; draw(); card(); } },
      h('span', { class: 'rbody' },
        h('span', { class: 'rname' }, h('span', { class: 'n' }, a.name), a.pings > 0 && pill(`${a.pings} PING${a.pings > 1 ? 'S' : ''}`, SEV[a.pingSeverity])),
        h('span', { class: 'rmeta' }, h('span', { class: 'm' }, `${envName(a.environment)} · ${pl(a.roles, 'role')} · median ${Math.round((a.never ?? 0) * 100)}% never called${a.complete ? '' : ` · ${a.progress}% read`}`))),
      h('span', { class: 'rval' }, h('span', { class: 'mono tiny' }, kfmt(a.excess)), h('span', { class: 'mono tiny', style: `color:${headColor(a.d30)}` }, headText(a.d30))))));
  }

  function card() {
    const a = sel; const T = E.totals;
    const worse = accounts.filter((x) => (x.d30 ?? 0) > 0.04).length, better = accounts.filter((x) => (x.d30 ?? 0) < -0.04).length;
    const trend = T.excess30 ? (T.excessNowComparable - T.excess30) / T.excess30 : null;
    const items = a ? F.items.filter((f) => f.account_id === a.id) : F.items;
    shell.right.replaceChildren(
      a ? h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, `ACCOUNT · ${envName(a.environment).toUpperCase()}`),
        h('div', { class: 'row', style: 'align-items:flex-start' }, h('h2', { class: 'grow', style: 'overflow-wrap:anywhere' }, a.name), !a.complete && h('span', { class: 'badge b-neutral' }, `${a.progress}% read`)),
        h('div', { class: 'tiny muted' }, [a.awsAccountId, a.ou, a.pooled != null ? `all its permissions together: ${Math.round(a.pooled * 100)}% never called` : null].filter(Boolean).join(' · ')))
        : h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'ESTATE'), h('h2', null, `${num(T.accounts)} accounts · ${num(T.roles)} roles`),
          h('div', { class: 'tiny muted' }, 'Distance = how much of its typical (median) role is never called · size = excess permissions · trail = where it was 30 days ago')),
      statGrid(a ? [['roles', num(a.roles), '#e3efe8'], ['excess permissions', kfmt(a.excess), '#f0b45a'], ['median role, never called', `${Math.round((a.never ?? 0) * 100)}%`, '#8fb5a1'], ['high-risk roles', num(a.high), '#ff8a7a']]
        : [['excess permissions', kfmt(T.excess), '#f0b45a'], ['change in 30 days', trend == null ? '—' : pct(trend, true), trend == null || Math.abs(trend) < 0.0005 ? '#7e978a' : trend > 0 ? '#f0b45a' : '#6fe3b0'],
          ['accounts getting worse', String(worse), '#f0b45a'], ['accounts improving', String(better), '#6fe3b0']]),
      a && h('div', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'eyebrow' }, 'HEADING · MEDIAN ROLE, NEVER CALLED · 30 DAYS'),
        trailEl(`account=${a.id}`, headColor(a.d30)),
        a.d30 != null && h('div', { class: 'small', style: `color:${headColor(a.d30)}` }, Math.abs(a.d30) < 0.01 ? 'Holding steady over 30 days.'
          : a.d30 > 0 ? `Drifting outward: ${headText(a.d30)} in 30 days. Permissions are granted faster than they are used.` : `Moving inward: ${headText(a.d30)} in 30 days. Cleanup is landing.`)),
      a && h('button', { class: 'btn primary', onClick: () => go(`#/?view=account&account=${a.id}`) }, 'Open this account on the radar'),
      !a && T.excess30 == null && h('p', { class: 'tiny muted' }, 'Trails and the 30-day trend fill in as daily snapshots accumulate. A snapshot is taken after each final analysis of a fully read account.'),
      feedSection(a ? `CHANGES IN ${a.name.toUpperCase()}` : 'CHANGES', { ...F, items }, (f) => { sel = accounts.find((x) => x.id === f.account_id) || null; draw(); card(); }));
  }

  // back to the estate summary: click empty dish, press Esc, or click the picked row again
  const unpick = () => { if (sel) { sel = null; draw(); card(); } };
  svgEl.addEventListener('click', unpick);
  const onKey = (ev) => { if (ev.key === 'Escape' && !ev.defaultPrevented && !document.querySelector('.win, .palette, dialog[open]')) unpick(); };
  document.addEventListener('keydown', onKey); ctx.onLeave?.(() => document.removeEventListener('keydown', onKey));
  // find an account: filters the list; Enter picks the first match
  const find = h('input', { type: 'search', placeholder: 'Find an account', 'aria-label': 'Find an account' });
  find.addEventListener('input', () => draw());
  find.addEventListener('keydown', (ev) => { if (ev.key !== 'Enter') return; const first = listEl.querySelector('.rank-row'); if (first) { ev.preventDefault(); first.click(); } });
  shell.left.append(controls, ...(accounts.length > 6 ? [find] : []), listEl);
  const wall = wallMode(ctx);
  const dayLabel = (n) => (n ? new Date(Date.now() - n * 864e5).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) : 'today');
  const hudNow = () => { const T = E.totals;
    const gone = accounts.filter((a) => a.absent).length;
    return hudEl(`RADAR · ESTATE${asOf ? ` · REPLAY ${dayLabel(asOf).toUpperCase()}` : ''} · ${num(T.accounts - gone)} ACCOUNTS${gone ? ` (${gone} NOT YET READ THEN)` : ''} · ${num(T.roles)} ROLES`,
      `${accounts.filter((a) => (a.d30 ?? 0) > 0.04).length} DRIFTING OUT · ${accounts.filter((a) => (a.d30 ?? 0) < -0.04).length} MOVING IN · ${num(F.total ?? F.items.length)} CHANGES · ${RANGE[F.days].toUpperCase()}`,
      'CONTACT = ACCOUNT · DISTANCE = MEDIAN ROLE, NEVER CALLED · SIZE = EXCESS · BRIGHTER = BUSIER IN 24 H'); };
  let hud = hudNow();
  // the replay: a slider over the last 90 days (right = today) and a play button that runs it forward to today
  let playing = null, loading = null;
  const range = h('input', { type: 'range', min: 0, max: 90, step: 1, value: 90 - asOf, 'aria-label': 'Replay: how many days ago to show the estate' });
  const when = h('span', { class: 'mono tiny' });
  const playBtn = h('button', { class: 'btn sm', 'aria-pressed': 'false' }, 'Play');
  const showWhen = () => { when.textContent = asOf ? `${dayLabel(asOf)} · ${asOf} day${asOf === 1 ? '' : 's'} ago` : 'Now'; range.setAttribute('aria-valuetext', when.textContent); };
  async function goBack(n) {
    asOf = n; showWhen();
    const mine = (loading = get(estateUrl()));
    const next = await mine; if (loading !== mine) return;
    E = next; accounts = E.accounts; prep();
    sel = sel && accounts.find((a) => a.id === sel.id);
    const fresh = hudNow(); hud.replaceWith(fresh); hud = fresh;
    draw(); card();
  }
  const stopPlay = () => { if (playing) { clearInterval(playing); playing = null; playBtn.textContent = 'Play'; playBtn.setAttribute('aria-pressed', 'false'); } };
  let t = null;
  range.addEventListener('input', () => { stopPlay(); const n = 90 - Number(range.value); asOf = n; showWhen(); clearTimeout(t); t = setTimeout(() => goBack(n), 120); });
  playBtn.addEventListener('click', () => {
    if (playing) return stopPlay();
    if (!asOf) { range.value = 60; goBack(30); }
    playBtn.textContent = 'Pause'; playBtn.setAttribute('aria-pressed', 'true');
    playing = setInterval(() => { if (!svgEl.isConnected) return stopPlay(); if (!asOf) return stopPlay(); range.value = 90 - (asOf - 1); goBack(asOf - 1); }, 700);
  });
  ctx.onLeave?.(stopPlay);
  showWhen();
  const replay = h('div', { class: 'replay' }, h('span', { class: 'eyebrow' }, 'Replay'), playBtn, range, when, wall.button);
  shell.scene.append(svgEl, replay,
    hud,
    legend([['width:10px;height:10px;border-radius:50%;background:#6fe3b0', 'Account (size = excess)'], ['width:10px;height:10px;border-radius:50%;background:#ff8a7a', '8+ high-risk roles'],
      ['width:16px;border-top:2px solid #f0b45a', 'Drifting out (30 d)'], ['width:16px;border-top:2px solid #6fe3b0', 'Moving in'],
      ['width:10px;height:10px;border-radius:50%;border:1.5px solid #ff5a4f;box-sizing:border-box', 'Ping: change that matters'],
      ['width:10px;height:10px;border-radius:50%;border:1.2px dashed #8ec5ff;box-sizing:border-box', 'New account'],
      ['width:10px;height:10px;border-radius:50%;border:1.4px solid #f6e016;box-sizing:border-box', 'History still loading']]));
  draw(); card(); onResize(svgEl, draw);
}

// ---------------------------------------------------------------- one account
async function accountView(ctx, shell) {
  let id = ctx.params.get('account');
  if (!id) {
    const E = await get(`/radar/estate${whoQs(ctx.who)}`);
    const pick = E.accounts.slice().sort((x, y) => y.pings - x.pings || y.excess - x.excess)[0];
    if (!pick) { shell.scene.append(h('div', { class: 'card empty', style: 'margin:40px' }, 'No accounts yet.')); return; }
    id = pick.id;
  }
  const [D, F] = await Promise.all([get(`/radar/account/${id}${whoQs(ctx.who)}`), get(`/changes?account=${id}&days=${feedDays(ctx)}`)]);
  const acct = D.account, roles = D.roles;
  ctx.setCrumbs(h('a', { href: '#/' }, 'Radar'), acct.name);
  for (const r of roles) r.d30 = drift(r.never, r.never30 ?? r.never7);
  const ranked = roles.slice().sort((x, y) => (!!y.ping - !!x.ping) || (y.risk === 'High') - (x.risk === 'High') || (y.d30 ?? 0) - (x.d30 ?? 0) || y.excess - x.excess);
  let sel = ranked.find((r) => r.id === ctx.params.get('role')) || ranked[0];
  const maxEx = Math.max(1, ...roles.map((r) => r.excess)), maxAct = Math.max(1, ...roles.map((r) => r.calls24h));
  const kinds = Object.keys(KIND_LABEL);
  const secs = sectors(kinds.map((k) => ({ id: k, name: KIND_LABEL[k].toUpperCase(), list: roles.filter((r) => r.kind === k) })).filter((g) => g.list.length).map((g) => ({ ...g, weight: g.list.length })), roles.length, 5);
  for (const s of secs) {
    const list = s.list.slice().sort((x, y) => x.name.localeCompare(y.name));
    list.forEach((r, i) => { r.ang = s.a0 + 1.5 + ((i + 0.5) / list.length) * (s.a1 - s.a0 - 3); r.rad = r.dead ? RAD(1) + 4 : RAD(r.never) - 4; [r.x, r.y] = P(r.ang, r.rad);
      // log scale: one admin-size role no longer shrinks every other role to a dot
      r.s = r1(3 + 7 * (Math.log1p(Math.max(0, r.excess)) / Math.log1p(maxEx))); });
  }
  const svgEl = stage(`Account radar for ${acct.name}: each contact is a role. Distance is its share of permissions never called; size is its excess; trails show where it was 30 days ago.`);
  const listEl = h('div', { class: 'rank-list' });
  const search = h('input', { type: 'search', placeholder: 'Find a role', 'aria-label': 'Find a role' });
  search.addEventListener('input', () => list());

  function draw() {
    textScale(svgEl);
    const kids = []; const top = base(kids, ZONE_RINGS, ZONE_LABELS);
    drawSectors(kids, secs, (s) => pl(s.list.length, s.id === 'iam-user' ? 'user' : 'role'));
    top();
    for (const r of roles) if (!r.dead && (r.never30 != null || r.never7 != null)) trail(kids, r.ang, r.never30 ?? r.never7, r.never7, r.never, Math.abs(r.d30 ?? 0) > 0.06 ? r.d30 : 0);
    for (const r of roles) {
      const hot = r.risk === 'High' || r.ping || Math.abs(r.d30 ?? 0) > 0.08 || r.unidentified;
      contact(kids, { d: shape(r.kind, r.x, r.y, r.s), x: r.x, y: r.y, s: r.s, fill: r.risk === 'High' ? '#ff8a7a' : '#6fe3b0', base: hot ? 0.9 : 0.4, act: r.calls24h / maxAct, ang: r.ang,
        sel: r === sel, isNew: r.isNew, title: `${r.name} · ${Math.round(r.never * 100)}% never called · ${num(r.granted)} granted`, onClick: () => { sel = r; draw(); list(); card(); } });
      if (r.unidentified) kids.push(svg('circle', { cx: r.x, cy: r.y, r: r1(r.s + 3), fill: 'none', stroke: '#f0b45a', 'stroke-dasharray': '3 2', 'pointer-events': 'none' }));
    }
    for (const r of roles) if (r.ping) ping(kids, r.x, r.y, r.s + 4, SEV[r.ping.severity], r.ang);
    tags(kids, [{ ...sel, text: short(sel.name, 28), color: '#f6e016' }].concat(ranked.filter((r) => r !== sel).slice(0, 14).map((r) => ({ ...r, text: short(r.name, 22), color: r.ping ? SEV[r.ping.severity] : r.risk === 'High' ? '#ff8a7a' : '#f0b45a' }))), 10);
    const d = drift(acct.never, null);
    void d;
    const total = roles.reduce((t, r) => t + r.excess, 0);
    const g30 = roles.filter((r) => r.never30 != null);
    const dAcc = g30.length ? g30.reduce((t, r) => t + r.never - r.never30, 0) / g30.length : null;
    dial(kids, 'ACCOUNT EXCESS', kfmt(total), '#f6e016', dAcc == null ? 'trend after 30 d' : `${headText(dAcc)} · 30 D`, headColor(dAcc));
    svgEl.replaceChildren(...kids);
  }
  function list() {
    const q = search.value.toLowerCase(), hits = ranked.filter((r) => !q || r.name.toLowerCase().includes(q));
    if (!hits.length) { listEl.replaceChildren(h('p', { class: 'tiny muted', style: 'padding:8px' }, q ? `No role matches “${search.value}”.` : 'No roles.')); return; }
    listEl.replaceChildren(...hits.slice(0, 400).map((r) => h('button', { class: 'rank-row', 'aria-pressed': String(r === sel), onClick: () => { sel = r; draw(); list(); card(); } },
      h('span', { class: 'rbody' },
        h('span', { class: 'rname' }, h('span', { class: 'n' }, r.name), r.ping && pill(CHANGE_KIND[r.ping.kind], SEV[r.ping.severity]), !r.ping && r.isNew && pill('NEW', '#8ec5ff'), r.unidentified && h('span', { class: 'unk-tag' }, 'UNK')),
        h('span', { class: 'rmeta' }, h('span', { class: 'm' }, `${KIND_LABEL[r.kind]} · ${num(r.granted)} granted${r.dead ? ' · no calls' : ''}`))),
      h('span', { class: 'rval' }, h('span', { class: 'mono tiny', style: `color:${r.dead ? '#ff8a7a' : r.never > 0.75 ? '#ffd89a' : '#9fe8c4'}` }, `${Math.round(r.never * 100)}%`),
        h('span', { class: 'mono tiny', style: `color:${headColor(r.d30)}` }, headText(r.d30))))),
      ...(hits.length > 400 ? [h('p', { class: 'tiny muted', style: 'padding:8px' }, `Showing 400 of ${num(hits.length)}. Type to narrow the list.`)] : []));
  }
  async function card() {
    const r = sel;
    if (!ctx.inWindow) syncUrl({ view: 'account', account: id, who: ctx.who === 'all' ? null : ctx.who, feed: F.days === 7 ? null : F.days, role: r.id });
    const items = F.items.filter((f) => f.role_id === r.id);
    shell.right.replaceChildren(
      h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, `ROLE · ${acct.name.toUpperCase()}`),
        h('div', { class: 'row', style: 'align-items:flex-start' }, h('h2', { class: 'grow', style: 'overflow-wrap:anywhere' }, r.name), h('span', { class: `badge ${riskClass(r.risk)}` }, r.risk)),
        h('div', { class: 'tiny muted' }, `${KIND_LABEL[r.kind]}${r.isNew ? ' · new this week' : ''}`)),
      statGrid([['granted', num(r.granted), '#e3efe8'], ['excess', num(r.excess), '#f0b45a'], ['never called', `${Math.round(r.never * 100)}%`, '#8fb5a1'], ['calls, last 24 h', num(r.calls24h), '#6fe3b0']]),
      h('div', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'eyebrow' }, 'HEADING · NEVER CALLED · 30 DAYS'), trailEl(`role=${r.id}`, headColor(r.d30))),
      h('a', { class: 'btn primary', href: `#/identities/${r.id}?tab=permissions` }, 'Sector scan'),
      h('div', { class: 'row' }, h('a', { class: 'btn sm grow', href: `#/identities/${r.id}` }, 'Role details'), h('a', { class: 'btn sm grow', href: `#/track?role=${r.id}` }, 'Track a session')),
      feedSection(items.length ? 'CHANGES TO THIS ROLE' : `CHANGES IN ${acct.name.toUpperCase()}`, { ...F, items: items.length ? items : F.items }, (f) => { const x = roles.find((y) => y.id === f.role_id); if (x) { sel = x; draw(); list(); card(); } }));
  }

  shell.left.append(h('div', { class: 'stack', style: 'gap:6px' },
    h('a', { href: '#/', class: 'small' }, `← All ${''}accounts`),
    h('h2', { style: 'overflow-wrap:anywhere' }, acct.name),
    h('div', { class: 'tiny muted' }, [acct.awsAccountId, envName(acct.environment), acct.ou].filter(Boolean).join(' · ')),
    !acct.complete && h('div', { class: 'tiny', style: 'color:#f6e016' }, `History ${acct.progress}% read · provisional`)),
  h('div', { class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'eyebrow' }, 'ROLES · PINGS AND RISK FIRST'), h('span', { class: 'mono tiny muted' }, String(roles.length))), search, listEl);
  shell.scene.append(svgEl,
    hudEl(`RADAR · ${acct.name.toUpperCase()} · ${num(roles.length)} ROLES`,
      `${roles.filter((r) => (r.d30 ?? 0) > 0.06).length} DRIFTING OUT · ${roles.filter((r) => (r.d30 ?? 0) < -0.06).length} MOVING IN · ${roles.filter((r) => r.ping).length} PINGS`,
      'CONTACT = ROLE · SECTOR = KIND · DISTANCE = NEVER CALLED · SIZE = EXCESS'),
    legend([['width:10px;height:10px;border-radius:50%;background:#6fe3b0', 'Custom'], ['width:9px;height:9px;background:#6fe3b0', 'Identity Center'],
      ['width:8px;height:8px;transform:rotate(45deg);background:#6fe3b0', 'Service-linked'], ['width:16px;border-top:2px solid #f0b45a', 'Drifting out'], ['width:16px;border-top:2px solid #6fe3b0', 'Moving in'],
      ['width:10px;height:10px;border-radius:50%;border:1.5px solid #ff5a4f;box-sizing:border-box', 'Ping'], ['width:10px;height:10px;border-radius:50%;border:1.2px dashed #8ec5ff;box-sizing:border-box', 'New role'],
      ['width:10px;height:10px;border-radius:50%;border:1.4px dashed #f0b45a;box-sizing:border-box', 'Unidentified calls']]));
  if (!roles.length) { shell.scene.append(h('div', { class: 'card empty', style: 'position:absolute;inset:auto 40px 80px' }, 'No roles in this account yet.')); return; }
  draw(); list(); card(); onResize(svgEl, draw);
}


function statGrid(items) {
  return h('div', { class: 'stat-grid' }, items.map(([k, v, c]) => h('div', null, h('span', { class: 'mono', style: `color:${c};font-size:17px` }, v), h('span', { class: 'tiny muted' }, k))));
}
function pill(text, color) { const s = h('span', { class: 'pill' }, text); s.style.color = paint(color); s.style.borderColor = paint(color); return s; }
