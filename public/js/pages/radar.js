// Radar v3. Three views, one dish:
//   Estate      — each contact is an AWS account. Distance = share of permissions never called; size = excess
//                 permissions; trail = where it was 7 and 30 days ago; the sweep is the last 24 h (contacts echo with
//                 activity); pings = changes that matter.
//   Account     — the same for one account's roles, sectored by kind.
//   Blast radius — one identity at the centre; rings are hops (direct trust, then each role chained); slices are the
//                 accounts reached.
import { h, svg, get, post, num, ago } from '../lib.js';
import { go } from '../main.js';

const CX = 400, CY = 400;
const SEV = { high: '#ff6b5e', warn: '#f0b45a', info: '#8ec5ff', good: '#6fe3b0' };
const KIND = { 'new-caller': 'NEW CALLER', denied: 'DENIED', grew: 'GREW', unidentified: 'UNIDENTIFIED', 'new-role': 'NEW ROLE', dead: 'DEAD', cleaned: 'CLEANED' };
const KIND_LABEL = { custom: 'Custom', 'identity-center': 'Identity Center', 'service-linked': 'Service-linked' };
const ENV_ORDER = ['production', 'shared', 'staging', 'development', 'sandbox'];
const ui = { group: 'env', chip: null };          // remembered while you move between views
const r1 = (v) => Math.round(v * 10) / 10;
const P = (deg, r) => { const a = ((deg - 90) * Math.PI) / 180; return [r1(CX + Math.cos(a) * r), r1(CY + Math.sin(a) * r)]; };
const RAD = (s) => 56 + Math.max(0, Math.min(1, s ?? 0)) * 258;
const still = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const kfmt = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}k` : num(Math.round(n)));
const shape = (kind, x, y, s) => kind === 'identity-center' ? `M${r1(x - s)} ${r1(y - s)}h${r1(2 * s)}v${r1(2 * s)}h${r1(-2 * s)}Z`
  : kind === 'service-linked' ? `M${x} ${r1(y - s * 1.3)}L${r1(x + s * 1.3)} ${y}L${x} ${r1(y + s * 1.3)}L${r1(x - s * 1.3)} ${y}Z`
  : `M${r1(x - s)} ${y}a${s} ${s} 0 1 0 ${r1(2 * s)} 0a${s} ${s} 0 1 0 ${r1(-2 * s)} 0Z`;
const beginAt = (deg) => `${(((deg % 360) + 360) % 360 / 360 * 8).toFixed(2)}s`;      // when the sweep reaches this bearing
const drift = (now, past) => (now == null || past == null ? null : now - past);
const headColor = (d) => (d == null ? '#7e978a' : d > 0.04 ? '#f0b45a' : d < -0.04 ? '#6fe3b0' : '#7e978a');
const headText = (d) => (d == null ? '· no trail yet' : Math.abs(d) < 0.01 ? '· flat' : `${d > 0 ? '▲' : '▼'} ${Math.abs(d * 100).toFixed(1)} pts`);
const short = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));
const riskClass = (r) => ({ High: 'b-high', Medium: 'b-medium', Low: 'b-low' })[r] || 'b-neutral';

export async function radarPage(ctx) {
  const view = ctx.params.get('view') || 'estate';
  const tabs = h('div', { class: 'rtabs', role: 'tablist', 'aria-label': 'Radar view' },
    [['estate', 'Estate'], ['account', 'Account'], ['blast', 'Blast radius']].map(([k, label]) => h('button', { role: 'tab', 'aria-selected': String(view === k),
      onClick: () => go(k === 'estate' ? '#/' : k === 'account' ? `#/?view=account${ctx.params.get('account') ? `&account=${ctx.params.get('account')}` : ''}` : '#/?view=blast') }, label)));
  const shell = { left: h('aside', { class: 'left' }), scene: h('div', { class: 'scene' }), right: h('aside', { class: 'right' }) };
  shell.left.append(tabs);
  const page = h('div', { class: 'stack radar-page radar3', style: 'gap:0' }, h('div', { class: 'scene-layout radar-layout' }, shell.left, shell.scene, shell.right));
  if (view === 'account') await accountView(ctx, shell);
  else if (view === 'blast') await blastView(ctx, shell);
  else await estateView(ctx, shell);
  return page;
}

// ---------------------------------------------------------------- shared drawing
function base(kids, rings, ringLabels) {
  kids.push(svg('defs', null,
    svg('filter', { id: 'g3', x: '-80%', y: '-80%', width: '260%', height: '260%' }, svg('feGaussianBlur', { stdDeviation: 2.6, result: 'b' }),
      svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' }))),
    svg('radialGradient', { id: 'sw3', cx: 0, cy: 0, r: 330, gradientUnits: 'userSpaceOnUse' },
      svg('stop', { offset: 0, 'stop-color': '#f6e016', 'stop-opacity': 0.18 }), svg('stop', { offset: 1, 'stop-color': '#f6e016', 'stop-opacity': 0.02 }))));
  kids.push(svg('circle', { cx: CX, cy: CY, r: 324, fill: '#051209', stroke: '#1f4a35' }));
  for (const [r, fill, dash] of rings) kids.push(svg('circle', { cx: CX, cy: CY, r: r1(r), fill, stroke: '#1a4231', 'stroke-dasharray': dash }));
  return () => {     // call after sectors: labels and sweep go on top of them
    for (const [t, rr, color] of ringLabels) {
      const y = r1(CY - rr + 4), bw = t.length * 6.6 + 10;
      kids.push(svg('rect', { x: r1(CX - bw / 2), y: r1(y - 11.5), width: r1(bw), height: 16, fill: '#030d08', opacity: 0.85, 'pointer-events': 'none' }),
        svg('text', { x: CX, y, 'text-anchor': 'middle', fill: color, 'font-family': 'Geist Mono, monospace', 'font-size': 10, 'letter-spacing': 1.2, 'pointer-events': 'none' }, t));
    }
    if (!still()) kids.push(svg('g', { transform: `translate(${CX} ${CY})`, 'pointer-events': 'none' }, svg('g', null,
      svg('path', { d: 'M0 0 L0 -330 A330 330 0 0 0 -165 -285.8 Z', fill: 'url(#sw3)' }), svg('path', { d: 'M0 0 L0 -330', stroke: '#f6e016', 'stroke-opacity': 0.6, 'stroke-width': 2 }),
      svg('animateTransform', { attributeName: 'transform', type: 'rotate', from: '0', to: '360', dur: '8s', repeatCount: 'indefinite' }))));
  };
}
const ZONE_RINGS = [[RAD(1) + 8, '#130f0b', null], [RAD(0.995), '#0b1c11', null], [RAD(0.75), '#081a10', '3 5'], [RAD(0.25), '#06160e', '3 5']];
const ZONE_LABELS = [['DEAD', RAD(1) + 6, '#ffb3aa'], ['BLOATED · >75%', RAD(0.87), '#ffd89a'], ['LOOSE', RAD(0.5), '#c9d98a'], ['TIGHT', RAD(0.12), '#9fe8c4']];

function sectors(groups, total, gap) {
  const span = 360 - gap * groups.length; let a0 = 0;
  return groups.map((g) => { const w = (span * g.weight) / Math.max(total, 1); const s = { ...g, a0: a0 + gap / 2, a1: a0 + gap / 2 + w }; a0 += w + gap; return s; });
}
function drawSectors(kids, secs, sub, onClick) {
  for (const s of secs) {
    const [ex0, ey0] = P(s.a0 - 2, 56), [ex1, ey1] = P(s.a0 - 2, 324), [ax0, ay0] = P(s.a0, 324), [ax1, ay1] = P(s.a1, 324);
    if (secs.length > 1) kids.push(svg('path', { d: `M${ex0} ${ey0} L${ex1} ${ey1}`, stroke: '#2a5c45', 'stroke-width': 1.2 }));
    kids.push(svg('path', { d: `M${ax0} ${ay0} A324 324 0 ${s.a1 - s.a0 > 180 ? 1 : 0} 1 ${ax1} ${ay1}`, fill: 'none', stroke: s.color || '#2f6e52', 'stroke-width': 3 }, svg('title', null, `${s.name} · ${sub(s)}`)));
    if (s.a1 - s.a0 < 10) continue;
    const mid = (s.a0 + s.a1) / 2; const [lx, lyr] = P(mid, 344); const ly = r1(lyr + (lyr < CY ? -8 : 6));
    const anchor = Math.abs(lx - CX) < 40 ? 'middle' : lx > CX ? 'start' : 'end';
    const t2 = sub(s); const fit = (w) => (anchor === 'start' ? Math.min(lx, 906 - w) : anchor === 'end' ? Math.max(lx, -106 + w) : lx);
    kids.push(svg('g', onClick ? { style: 'cursor:pointer', onClick: (e) => { e.stopPropagation(); onClick(s); } } : null,
      svg('text', { x: r1(fit(s.name.length * 7.3)), y: ly, 'text-anchor': anchor, fill: '#e3efe8', 'font-family': 'Geist Mono, monospace', 'font-size': 12 }, s.name),
      svg('text', { x: r1(fit(t2.length * 5.6)), y: ly + 14, 'text-anchor': anchor, fill: '#7e978a', 'font-size': 11 }, t2)));
  }
}
function contact(kids, c) {
  // c: { d, x, y, fill, stroke, base, act, ang, title, sel, isNew, onClick }
  const g = svg('g', { style: 'cursor:pointer', onClick: (e) => { e.stopPropagation(); c.onClick?.(); } }, svg('title', null, c.title));
  const body = svg('path', { d: c.d, fill: c.fill, stroke: c.stroke || null, 'stroke-width': c.stroke ? 1.4 : null, opacity: c.base });
  if (!still() && c.act != null) {
    body.append(svg('animate', { attributeName: 'opacity', values: `${c.base};${r1(Math.min(1, c.base + 0.15 + c.act * 0.85))};${c.base};${c.base}`, keyTimes: '0;0.015;0.3;1', dur: '8s', begin: beginAt(c.ang), repeatCount: 'indefinite' }));
  }
  g.append(body);
  if (c.isNew) g.append(svg('circle', { cx: c.x, cy: c.y, r: r1(c.s + 4), fill: 'none', stroke: '#8ec5ff', 'stroke-width': 1.2, 'stroke-dasharray': '2 2' }));
  if (c.sel) g.append(svg('circle', { cx: c.x, cy: c.y, r: r1(c.s + 6), fill: 'none', stroke: '#f6e016', 'stroke-width': 1.5 }));
  kids.push(g);
}
function ping(kids, x, y, r, color, ang) {
  const g = svg('g', { 'pointer-events': 'none' }, svg('circle', { cx: x, cy: y, r: r1(r), fill: 'none', stroke: color, 'stroke-width': 1.4 }));
  if (!still()) g.append(svg('circle', { cx: x, cy: y, r: 6, fill: 'none', stroke: color, 'stroke-width': 2, opacity: 0 },
    svg('animate', { attributeName: 'r', values: '6;34;34', keyTimes: '0;0.16;1', dur: '8s', begin: beginAt(ang), repeatCount: 'indefinite' }),
    svg('animate', { attributeName: 'opacity', values: '1;0;0', keyTimes: '0;0.16;1', dur: '8s', begin: beginAt(ang), repeatCount: 'indefinite' })));
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
  const placed = [[CX - 60, CY - 50, CX + 60, CY + 50], ...extraBoxes]; let n = 0;
  for (const c of cands) {
    if (n >= max) break;
    const bw = c.text.length * 6.6 + 10;
    for (const push of [16, 32, -20, 48]) {
      const [tx, ty] = P(c.ang, c.rad + push); const left = tx < CX; const bx = left ? tx - bw : tx, by = ty - 9;
      const box = [bx, by, bx + bw, by + 18];
      if (box[0] < -100 || box[2] > 900 || box[1] < 4 || box[3] > 796) continue;
      if (placed.some((q) => box[0] < q[2] + 2 && box[2] > q[0] - 2 && box[1] < q[3] + 2 && box[3] > q[1] - 2)) continue;
      placed.push(box); n++;
      kids.push(svg('g', { 'pointer-events': 'none' },
        svg('path', { d: `M${c.x} ${c.y} L${r1(left ? bx + bw : bx)} ${r1(by + 9)}`, stroke: c.color, 'stroke-width': 1, opacity: 0.7 }),
        svg('rect', { x: r1(bx), y: r1(by), width: r1(bw), height: 18, fill: '#030d08', stroke: c.color, 'stroke-width': 1 }),
        svg('text', { x: r1(bx + 5), y: r1(by + 13), fill: c.color, 'font-family': 'Geist Mono, monospace', 'font-size': 10.5 }, c.text)));
      break;
    }
  }
}
function dial(kids, top, value, color, trend, trendColor) {
  kids.push(svg('circle', { cx: CX, cy: CY, r: 46, fill: '#030d08', stroke: '#2a5c45' }),
    svg('text', { x: CX, y: CY - 11, 'text-anchor': 'middle', fill: '#7e978a', 'font-family': 'Geist Mono, monospace', 'font-size': 8.5, 'letter-spacing': 1 }, top),
    svg('text', { x: CX, y: CY + 8, 'text-anchor': 'middle', fill: color, 'font-size': 19, 'font-weight': 500 }, value),
    svg('text', { x: CX, y: CY + 23, 'text-anchor': 'middle', fill: trendColor, 'font-family': 'Geist Mono, monospace', 'font-size': 9.5 }, trend));
}
const stage = (label) => svg('svg', { class: 'stage', viewBox: '-110 0 1020 800', preserveAspectRatio: 'xMidYMid meet', role: 'img', 'aria-label': label });
const hudEl = (a, b, c) => h('div', { class: 'hud' }, h('div', { class: 'hot' }, `● ${a}`), h('div', null, b), h('div', null, c));
function legend(items) {
  return h('div', { class: 'legend' }, items.map(([sw, t]) => { const s = h('span', { 'aria-hidden': 'true' }); s.style.cssText = sw; return h('span', null, s, t); }));
}
function spark(points, color) {
  const vals = points.filter((v) => v != null); if (vals.length < 2) return null;
  const xs = [0, 230, 300]; const pts = points.map((v, i) => (v == null ? null : `${xs[i]},${r1(50 - v * 46)}`)).filter(Boolean).join(' ');
  return svg('svg', { viewBox: '0 0 300 54', style: 'width:100%;height:54px', role: 'img', 'aria-label': `Never-called share: ${points.filter((v) => v != null).map((v) => `${Math.round(v * 100)}%`).join(' → ')}` },
    svg('path', { d: 'M0 53 H300', stroke: '#143425' }), svg('polyline', { points: pts, fill: 'none', stroke: color, 'stroke-width': 1.6 }));
}
function feedList(items, seenAt, onPick) {
  if (!items.length) return h('p', { class: 'tiny muted' }, 'No changes in the last 7 days. Changes are recorded once an account’s history is fully read, from one daily analysis to the next.');
  return h('div', { class: 'stack', style: 'gap:6px' }, items.map((f) => {
    const fresh = seenAt && new Date(f.at) > new Date(seenAt);
    const b = h('button', { class: 'feed-item', onClick: () => onPick?.(f) },
      h('span', { class: 'row mono tiny', style: 'justify-content:space-between' }, h('span', { style: `color:${SEV[f.severity]};letter-spacing:.06em` }, KIND[f.kind] || f.kind, fresh ? h('span', { class: 'fresh' }, ' NEW') : null), h('span', { class: 'faint' }, ago(f.at))),
      h('span', { class: 'small', style: 'line-height:1.4' }, f.title),
      h('span', { class: 'tiny faint', style: 'overflow-wrap:anywhere' }, [f.account_name, f.detail].filter(Boolean).join(' · ')));
    b.style.borderLeftColor = SEV[f.severity]; return b;
  }));
}

// ---------------------------------------------------------------- estate
async function estateView(ctx, shell) {
  ctx.setCrumbs('Radar', 'Estate');
  const [E, F] = await Promise.all([get('/radar/estate'), get('/changes')]);
  post('/changes/seen').catch(() => {});
  const accounts = E.accounts;
  if (!accounts.length) { shell.scene.append(h('div', { class: 'card empty', style: 'margin:40px' }, 'No accounts yet. ', h('a', { href: '#/accounts/new' }, 'Connect an AWS account'))); return; }
  for (const a of accounts) { a.d30 = drift(a.never, a.never30); a.d7 = drift(a.never, a.never7); }
  let sel = null;
  const maxEx = Math.max(1, ...accounts.map((a) => a.excess)), maxAct = Math.max(1, ...accounts.map((a) => a.calls24h));
  const CHIPS = [['worse', 'Getting worse', '#f0b45a', (a) => (a.d30 ?? 0) > 0.04], ['better', 'Improving', '#6fe3b0', (a) => (a.d30 ?? 0) < -0.04],
    ['pinged', 'Has pings', '#ff6b5e', (a) => a.pings > 0], ['loading', 'Loading', '#f6e016', (a) => !a.complete]];
  const svgEl = stage('Estate radar: each contact is an AWS account. Distance is its share of permissions never called; size is its excess permissions; trails show where it was 7 and 30 days ago.');
  const listEl = h('div', { class: 'rank-list' }), controls = h('div', { class: 'stack', style: 'gap:10px' });
  const hasOu = accounts.some((a) => a.ou);

  function draw() {
    const cf = ui.chip ? CHIPS.find((c) => c[0] === ui.chip)[3] : null;
    const key = (a) => (ui.group === 'ou' ? a.ou || 'No OU set' : a.environment);
    const order = ui.group === 'ou' ? [...new Set(accounts.map(key))].sort() : [...new Set(accounts.map(key))].sort((x, y) => (ENV_ORDER.indexOf(x) + 1 || 9) - (ENV_ORDER.indexOf(y) + 1 || 9));
    const groups = order.map((k) => ({ id: k, name: k.toUpperCase(), list: accounts.filter((a) => key(a) === k) })).map((g) => ({ ...g, weight: g.list.length }));
    const secs = sectors(groups, accounts.length, 5);
    for (const s of secs) {
      const list = s.list.slice().sort((x, y) => x.name.localeCompare(y.name));
      list.forEach((a, i) => { a.ang = s.a0 + 1.5 + ((i + 0.5) / list.length) * (s.a1 - s.a0 - 3); a.rad = RAD(a.never); [a.x, a.y] = P(a.ang, a.rad); a.s = r1(3 + Math.sqrt(Math.max(0, a.excess) / maxEx) * 13); });
    }
    const kids = []; const top = base(kids, ZONE_RINGS, ZONE_LABELS);
    drawSectors(kids, secs, (s) => `${s.list.length} accts · ${num(s.list.reduce((t, x) => t + x.roles, 0))} roles`);
    top();
    for (const a of accounts) if (!cf || cf(a)) trail(kids, a.ang, a.never30, a.never7, a.never, a.d30 ?? 0);
    for (const a of accounts) {
      const on = !cf || cf(a);
      contact(kids, { d: shape('custom', a.x, a.y, a.s), x: a.x, y: a.y, s: a.s, fill: !a.complete ? '#030d08' : a.high >= 8 ? '#ff8a7a' : '#6fe3b0', stroke: !a.complete ? '#f6e016' : null,
        base: on ? 0.45 : 0.1, act: on ? a.calls24h / maxAct : 0, ang: a.ang, sel: sel === a, isNew: a.isNew,
        title: `${a.name} · ${a.roles} roles · ${Math.round((a.never ?? 0) * 100)}% never called · ${headText(a.d30)} in 30 days${a.complete ? '' : ` · ${a.progress}% read`}`,
        onClick: () => { sel = a; draw(); card(); } });
    }
    for (const a of accounts) if (a.pings && (!cf || cf(a))) ping(kids, a.x, a.y, a.s + 4, SEV[a.pingSeverity] || SEV.info, a.ang);
    const cands = [];
    if (sel) cands.push({ ...sel, text: sel.name, color: '#f6e016' });
    for (const a of accounts.filter((x) => x.pings && (!cf || cf(x))).sort((x, y) => ['high', 'warn', 'info', 'good'].indexOf(x.pingSeverity) - ['high', 'warn', 'info', 'good'].indexOf(y.pingSeverity))) cands.push({ ...a, text: a.name, color: SEV[a.pingSeverity] });
    for (const a of accounts.filter((x) => (x.d30 ?? 0) > 0.04 && (!cf || cf(x))).sort((x, y) => y.d30 - x.d30).slice(0, 5)) cands.push({ ...a, text: `${a.name} ${headText(a.d30).replace(' pts', '')}`, color: '#f0b45a' });
    const seen = new Set(); tags(kids, cands.filter((c) => (seen.has(c.id) ? false : seen.add(c.id))), 12);
    const T = E.totals; const trend = T.excess30 ? (T.excessNowComparable - T.excess30) / T.excess30 : null;
    dial(kids, 'ESTATE EXCESS', kfmt(T.excess), '#f6e016', trend == null ? 'trend after 30 d' : `${trend > 0 ? '▲' : '▼'} ${Math.abs(trend * 100).toFixed(1)}% · 30 D`, trend == null ? '#7e978a' : trend > 0 ? '#f0b45a' : '#6fe3b0');
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
    const listed = accounts.filter((a) => !cf || cf(a)).sort((x, y) => (ui.chip === 'better' ? (x.d30 ?? 0) - (y.d30 ?? 0) : ui.chip === 'worse' ? (y.d30 ?? 0) - (x.d30 ?? 0) : y.excess - x.excess));
    listEl.replaceChildren(...listed.map((a) => h('button', { class: 'rank-row', 'aria-pressed': String(sel === a), onClick: () => { sel = a; draw(); card(); } },
      h('span', { class: 'rbody' },
        h('span', { class: 'rname' }, h('span', { class: 'n' }, a.name), a.pings > 0 && pill(`${a.pings} PING${a.pings > 1 ? 'S' : ''}`, SEV[a.pingSeverity])),
        h('span', { class: 'rmeta' }, h('span', { class: 'm' }, `${a.environment} · ${num(a.roles)} roles · ${Math.round((a.never ?? 0) * 100)}% never called${a.complete ? '' : ` · ${a.progress}% read`}`))),
      h('span', { class: 'rval' }, h('span', { class: 'mono tiny' }, kfmt(a.excess)), h('span', { class: 'mono tiny', style: `color:${headColor(a.d30)}` }, headText(a.d30))))));
  }

  function card() {
    const a = sel; const T = E.totals;
    const worse = accounts.filter((x) => (x.d30 ?? 0) > 0.04).length, better = accounts.filter((x) => (x.d30 ?? 0) < -0.04).length;
    const trend = T.excess30 ? (T.excessNowComparable - T.excess30) / T.excess30 : null;
    const items = a ? F.items.filter((f) => f.account_id === a.id) : F.items;
    shell.right.replaceChildren(
      a ? h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, `ACCOUNT · ${a.environment.toUpperCase()}`),
        h('div', { class: 'row', style: 'align-items:flex-start' }, h('h2', { class: 'grow', style: 'overflow-wrap:anywhere' }, a.name), !a.complete && h('span', { class: 'badge b-neutral' }, `${a.progress}% read`)),
        h('div', { class: 'tiny muted' }, [a.awsAccountId, a.ou].filter(Boolean).join(' · ')))
        : h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'ESTATE'), h('h2', null, `${num(T.accounts)} accounts · ${num(T.roles)} roles`),
          h('div', { class: 'tiny muted' }, 'Distance = share of permissions never called · size = excess permissions · trail = where it was 30 days ago')),
      statGrid(a ? [['roles', num(a.roles), '#e3efe8'], ['excess permissions', kfmt(a.excess), '#f0b45a'], ['never-called share', `${Math.round((a.never ?? 0) * 100)}%`, '#8fb5a1'], ['high-risk roles', num(a.high), '#ff8a7a']]
        : [['excess permissions', kfmt(T.excess), '#f0b45a'], ['change in 30 days', trend == null ? '—' : `${trend > 0 ? '+' : ''}${(trend * 100).toFixed(1)}%`, trend == null ? '#7e978a' : trend > 0 ? '#f0b45a' : '#6fe3b0'],
          ['accounts getting worse', String(worse), '#f0b45a'], ['accounts improving', String(better), '#6fe3b0']]),
      a && h('div', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'eyebrow' }, 'HEADING · NEVER-CALLED SHARE, 30 DAYS'),
        spark([a.never30, a.never7, a.never], headColor(a.d30)) || h('p', { class: 'tiny muted' }, 'A trail appears once daily snapshots go back 7 days.'),
        a.d30 != null && h('div', { class: 'small', style: `color:${headColor(a.d30)}` }, Math.abs(a.d30) < 0.01 ? 'Holding steady over 30 days.'
          : a.d30 > 0 ? `Drifting outward: ${headText(a.d30)} in 30 days. Permissions are granted faster than they are used.` : `Moving inward: ${headText(a.d30)} in 30 days. Cleanup is landing.`)),
      a && h('button', { class: 'btn primary', onClick: () => go(`#/?view=account&account=${a.id}`) }, 'Open this account on the radar'),
      !a && T.excess30 == null && h('p', { class: 'tiny muted' }, 'Trails and the 30-day trend fill in as daily snapshots accumulate. A snapshot is taken after each final analysis of a fully read account.'),
      h('section', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'eyebrow' }, a ? `CHANGES IN ${a.name.toUpperCase()}` : `SINCE YOU LAST LOOKED · ${F.items.filter((f) => !F.seenAt || new Date(f.at) > new Date(F.seenAt)).length} NEW`),
        feedList(items, F.seenAt, (f) => { sel = accounts.find((x) => x.id === f.account_id) || null; draw(); card(); })));
  }

  const T = E.totals;
  shell.left.append(controls, listEl);
  shell.scene.append(svgEl,
    hudEl(`RADAR · ESTATE · ${num(T.accounts)} ACCOUNTS · ${num(T.roles)} ROLES`,
      `${accounts.filter((a) => (a.d30 ?? 0) > 0.04).length} DRIFTING OUT · ${accounts.filter((a) => (a.d30 ?? 0) < -0.04).length} MOVING IN · ${F.items.length} CHANGES IN 7 DAYS`,
      'CONTACT = ACCOUNT · DISTANCE = NEVER CALLED · SIZE = EXCESS · SWEEP = LAST 24 H'),
    legend([['width:10px;height:10px;border-radius:50%;background:#6fe3b0', 'Account (size = excess)'], ['width:10px;height:10px;border-radius:50%;background:#ff8a7a', '8+ high-risk roles'],
      ['width:16px;border-top:2px solid #f0b45a', 'Drifting out (30 d)'], ['width:16px;border-top:2px solid #6fe3b0', 'Moving in'],
      ['width:10px;height:10px;border-radius:50%;border:1.5px solid #ff6b5e;box-sizing:border-box', 'Ping: change that matters'],
      ['width:10px;height:10px;border-radius:50%;border:1.2px dashed #8ec5ff;box-sizing:border-box', 'New account'],
      ['width:10px;height:10px;border-radius:50%;border:1.4px solid #f6e016;box-sizing:border-box', 'History still loading']]));
  draw(); card();
}

// ---------------------------------------------------------------- one account
async function accountView(ctx, shell) {
  let id = ctx.params.get('account');
  if (!id) {
    const E = await get('/radar/estate');
    const pick = E.accounts.slice().sort((x, y) => y.pings - x.pings || y.excess - x.excess)[0];
    if (!pick) { shell.scene.append(h('div', { class: 'card empty', style: 'margin:40px' }, 'No accounts yet.')); return; }
    id = pick.id;
  }
  const [D, F] = await Promise.all([get(`/radar/account/${id}`), get(`/changes?account=${id}`)]);
  const acct = D.account, roles = D.roles;
  ctx.setCrumbs(h('a', { href: '#/' }, 'Radar'), acct.name);
  for (const r of roles) r.d30 = drift(r.never, r.never30 ?? r.never7);
  const ranked = roles.slice().sort((x, y) => (!!y.ping - !!x.ping) || (y.risk === 'High') - (x.risk === 'High') || (y.d30 ?? 0) - (x.d30 ?? 0) || y.excess - x.excess);
  let sel = ranked[0];
  const maxEx = Math.max(1, ...roles.map((r) => r.excess)), maxAct = Math.max(1, ...roles.map((r) => r.calls24h));
  const kinds = Object.keys(KIND_LABEL);
  const secs = sectors(kinds.map((k) => ({ id: k, name: KIND_LABEL[k].toUpperCase(), list: roles.filter((r) => r.kind === k) })).filter((g) => g.list.length).map((g) => ({ ...g, weight: g.list.length })), roles.length, 5);
  for (const s of secs) {
    const list = s.list.slice().sort((x, y) => x.name.localeCompare(y.name));
    list.forEach((r, i) => { r.ang = s.a0 + 1.5 + ((i + 0.5) / list.length) * (s.a1 - s.a0 - 3); r.rad = r.dead ? RAD(1) + 4 : RAD(r.never) - 4; [r.x, r.y] = P(r.ang, r.rad); r.s = r1(2 + Math.sqrt(Math.max(0, r.excess) / maxEx) * 9); });
  }
  const svgEl = stage(`Account radar for ${acct.name}: each contact is a role. Distance is its share of permissions never called; size is its excess; trails show where it was 30 days ago.`);
  const listEl = h('div', { class: 'rank-list' });
  const search = h('input', { type: 'search', placeholder: 'Find a role', 'aria-label': 'Find a role' });
  search.addEventListener('input', () => list());

  function draw() {
    const kids = []; const top = base(kids, ZONE_RINGS, ZONE_LABELS);
    drawSectors(kids, secs, (s) => `${s.list.length} roles`);
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
    const q = search.value.toLowerCase();
    listEl.replaceChildren(...ranked.filter((r) => !q || r.name.toLowerCase().includes(q)).slice(0, 400).map((r) => h('button', { class: 'rank-row', 'aria-pressed': String(r === sel), onClick: () => { sel = r; draw(); list(); card(); } },
      h('span', { class: 'rbody' },
        h('span', { class: 'rname' }, h('span', { class: 'n' }, r.name), r.ping && pill(KIND[r.ping.kind], SEV[r.ping.severity]), !r.ping && r.isNew && pill('NEW', '#8ec5ff'), r.unidentified && h('span', { class: 'unk-tag' }, 'UNK')),
        h('span', { class: 'rmeta' }, h('span', { class: 'm' }, `${KIND_LABEL[r.kind]} · ${num(r.granted)} granted${r.dead ? ' · no calls' : ''}`))),
      h('span', { class: 'rval' }, h('span', { class: 'mono tiny', style: `color:${r.dead ? '#ff8a7a' : r.never > 0.75 ? '#ffd89a' : '#9fe8c4'}` }, `${Math.round(r.never * 100)}%`),
        h('span', { class: 'mono tiny', style: `color:${headColor(r.d30)}` }, headText(r.d30))))));
  }
  async function card() {
    const r = sel;
    const items = F.items.filter((f) => f.role_id === r.id);
    shell.right.replaceChildren(
      h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, `ROLE · ${acct.name.toUpperCase()}`),
        h('div', { class: 'row', style: 'align-items:flex-start' }, h('h2', { class: 'grow', style: 'overflow-wrap:anywhere' }, r.name), h('span', { class: `badge ${riskClass(r.risk)}` }, r.risk)),
        h('div', { class: 'tiny muted' }, `${KIND_LABEL[r.kind]}${r.isNew ? ' · new this week' : ''}`)),
      statGrid([['granted', num(r.granted), '#e3efe8'], ['excess', num(r.excess), '#f0b45a'], ['never called', `${Math.round(r.never * 100)}%`, '#8fb5a1'], ['calls, last 24 h', num(r.calls24h), '#6fe3b0']]),
      h('div', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'eyebrow' }, 'HEADING · 30 DAYS'),
        spark([r.never30, r.never7, r.never], headColor(r.d30)) || h('p', { class: 'tiny muted' }, 'No trail yet: snapshots start once the account is fully read.')),
      h('a', { class: 'btn primary', href: `#/roles/${r.id}/scan` }, 'Sector scan'),
      h('div', { class: 'row' }, h('a', { class: 'btn sm grow', href: `#/roles/${r.id}` }, 'Role details'), h('a', { class: 'btn sm grow', href: `#/track?role=${r.id}` }, 'Track a session')),
      h('div', { class: 'stack', style: 'gap:6px', id: 'callers-blast' }),
      h('section', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'eyebrow' }, items.length ? 'CHANGES TO THIS ROLE' : `CHANGES IN ${acct.name.toUpperCase()}`),
        feedList(items.length ? items : F.items, F.seenAt, (f) => { const x = roles.find((y) => y.id === f.role_id); if (x) { sel = x; draw(); list(); card(); } })));
    // the role's callers, each one a way into blast radius
    const d = await get(`/roles/${r.id}`);
    if (sel !== r) return;
    const box = shell.right.querySelector('#callers-blast');
    const callers = d.principals.filter((p) => p.kind !== 'session').slice(0, 4);
    if (box && callers.length) box.replaceChildren(h('div', { class: 'eyebrow' }, 'BLAST RADIUS OF ITS CALLERS'),
      callers.map((p) => h('a', { class: 'btn sm', href: `#/?view=blast&key=${encodeURIComponent(p.key)}`, style: 'justify-content:flex-start;overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }, p.display)));
  }

  shell.left.append(h('div', { class: 'stack', style: 'gap:6px' },
    h('a', { href: '#/', class: 'small' }, `← All ${''}accounts`),
    h('h2', { style: 'overflow-wrap:anywhere' }, acct.name),
    h('div', { class: 'tiny muted' }, [acct.awsAccountId, acct.environment, acct.ou].filter(Boolean).join(' · ')),
    !acct.complete && h('div', { class: 'tiny', style: 'color:#f6e016' }, `History ${acct.progress}% read · provisional`)),
  h('div', { class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'eyebrow' }, 'ROLES · PINGS AND RISK FIRST'), h('span', { class: 'mono tiny muted' }, String(roles.length))), search, listEl);
  shell.scene.append(svgEl,
    hudEl(`RADAR · ${acct.name.toUpperCase()} · ${num(roles.length)} ROLES`,
      `${roles.filter((r) => (r.d30 ?? 0) > 0.06).length} DRIFTING OUT · ${roles.filter((r) => (r.d30 ?? 0) < -0.06).length} MOVING IN · ${roles.filter((r) => r.ping).length} PINGS`,
      'CONTACT = ROLE · SECTOR = KIND · DISTANCE = NEVER CALLED · SIZE = EXCESS'),
    legend([['width:10px;height:10px;border-radius:50%;background:#6fe3b0', 'Custom'], ['width:9px;height:9px;background:#6fe3b0', 'Identity Center'],
      ['width:8px;height:8px;transform:rotate(45deg);background:#6fe3b0', 'Service-linked'], ['width:16px;border-top:2px solid #f0b45a', 'Drifting out'], ['width:16px;border-top:2px solid #6fe3b0', 'Moving in'],
      ['width:10px;height:10px;border-radius:50%;border:1.5px solid #ff6b5e;box-sizing:border-box', 'Ping'], ['width:10px;height:10px;border-radius:50%;border:1.2px dashed #8ec5ff;box-sizing:border-box', 'New role'],
      ['width:10px;height:10px;border-radius:50%;border:1.4px dashed #f0b45a;box-sizing:border-box', 'Unidentified calls']]));
  if (!roles.length) { shell.scene.append(h('div', { class: 'card empty', style: 'position:absolute;inset:auto 40px 80px' }, 'No roles in this account yet.')); return; }
  draw(); list(); card();
}

// ---------------------------------------------------------------- blast radius
async function blastView(ctx, shell) {
  ctx.setCrumbs(h('a', { href: '#/' }, 'Radar'), 'Blast radius');
  const ids = (await get('/blast/identities')).items;
  const key = ctx.params.get('key') || ids[0]?.key;
  const listEl = h('div', { class: 'rank-list' });
  const search = h('input', { type: 'search', placeholder: 'Find an identity', 'aria-label': 'Find an identity' });
  let timer = 0;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(async () => { drawList((await get(`/blast/identities?q=${encodeURIComponent(search.value)}`)).items); }, 250); });
  const drawList = (items) => listEl.replaceChildren(...items.map((x) => h('button', { class: 'rank-row', 'aria-pressed': String(x.key === key), onClick: () => go(`#/?view=blast&key=${encodeURIComponent(x.key)}`) },
    h('span', { class: 'rbody' }, h('span', { class: 'rname' }, h('span', { class: 'n' }, x.display), x.reaches_admin && pill('ADMIN', '#ff6b5e')),
      h('span', { class: 'rmeta' }, h('span', { class: 'm' }, `${x.kind}${x.via ? ` · ${x.via}` : ''}`))),
    h('span', { class: 'rval' }, h('span', { class: 'mono tiny' }, `${x.roles} role${x.roles > 1 ? 's' : ''}`), h('span', { class: 'mono tiny faint' }, `${x.accounts} acct${x.accounts > 1 ? 's' : ''}`)))),
  !items.length ? h('p', { class: 'tiny muted', style: 'padding:8px' }, 'No identities seen entering roles yet.') : null);
  shell.left.append(h('p', { class: 'tiny muted', style: 'line-height:1.5' }, 'Pick an identity. The radar shows every role it can reach: roles it was seen entering, roles whose trust policy names it, and the same again from each role reached.'),
    search, h('div', { class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'eyebrow' }, 'IDENTITIES · DIRECT REACH FIRST'), h('span', { class: 'mono tiny muted' }, String(ids.length))), listEl);
  drawList(ids);
  if (!key) { shell.scene.append(h('div', { class: 'card empty', style: 'margin:40px' }, 'Nobody has been seen entering a role yet.')); return; }

  const B = await get(`/blast?key=${encodeURIComponent(key)}`);
  const nodes = B.nodes, byId = new Map(nodes.map((n) => [n.id, n]));
  const reached = [...new Set(nodes.map((n) => n.accountId))].map((aid) => nodes.find((n) => n.accountId === aid))
    .sort((x, y) => (x.environment === 'production') - (y.environment === 'production') || x.account.localeCompare(y.account)).reverse();
  const secs = sectors(reached.map((n) => ({ id: n.accountId, name: n.account, env: n.environment, weight: nodes.filter((x) => x.accountId === n.accountId).length, color: n.environment === 'production' ? '#7a3a30' : '#2f6e52' })), nodes.length, nodes.length > 1 ? 3 : 0);
  const HOP = [0, 120, 200, 270, 312];
  for (const s of secs) for (let hop = 1; hop <= 4; hop++) {
    const L = nodes.filter((n) => n.accountId === s.id && n.hop === hop);
    L.forEach((n, i) => { n.ang = s.a0 + 1 + ((i + 0.5) / L.length) * (s.a1 - s.a0 - 2); n.rad = HOP[hop]; [n.x, n.y] = P(n.ang, n.rad); n.s = r1(3 + Math.log10(Math.max(1, n.perms)) * 1.6); });
  }
  const maxHop = Math.max(1, ...nodes.map((n) => n.hop));
  const svgEl = stage(`Blast radius of ${B.identity.display}: the identity at the centre; rings are hops; slices are the accounts reached.`);
  const chainOf = (n) => { const c = []; let x = n; while (x) { c.unshift(x); x = x.parent ? byId.get(x.parent) : null; } return c; };
  let sel = null;                                       // { type: 'node', n } | { type: 'account', s }
  const bubble = h('div', { class: 'blast-pop', hidden: true, role: 'dialog', 'aria-label': 'Details' });

  // Clicking a node or slice selects it and opens a bubble beside it; the page never navigates on its own.
  function drawScene() {
    const kids = [];
    const onPath = sel?.type === 'node' ? new Set(chainOf(sel.n).map((x) => x.id)) : null;
    const inAcct = sel?.type === 'account' ? sel.s.id : null;
    const dim = (n) => (onPath ? !onPath.has(n.id) : inAcct ? n.accountId !== inAcct : false);
    const rings = [[HOP[Math.min(4, maxHop)] + 18, '#051209', null]].concat([4, 3, 2, 1].filter((h0) => h0 <= maxHop).map((h0) => [HOP[h0] + (h0 === 1 ? -40 : -36), h0 % 2 ? '#081a10' : '#0a1d12', '3 5']));
    const top = base(kids, rings, [[`HOP 1 · TRUSTS IT OR SEEN ENTERING`, HOP[1] + 14, '#a9bfb2'], ...(maxHop >= 2 ? [['HOP 2 · CHAINED', HOP[2] + 14, '#a9bfb2']] : []), ...(maxHop >= 3 ? [['HOP 3+', HOP[3] + 14, '#a9bfb2']] : [])]);
    drawSectors(kids, secs, (s) => `${s.weight} role${s.weight > 1 ? 's' : ''}${s.env === 'production' ? ' · prod' : ''}`, (s) => select({ type: 'account', s }));
    top();
    for (const n of nodes) {
      const from = n.parent ? byId.get(n.parent) : null;
      const color = n.admin ? '#ff6b5e' : n.hop === 1 ? '#6fe3b0' : '#8ec5ff';
      const d = from ? (() => { const [mx, my] = P((from.ang + n.ang) / 2, (from.rad + n.rad) / 2); return `M${from.x} ${from.y} Q${mx} ${my} ${n.x} ${n.y}`; })() : `M${CX} ${CY} L${n.x} ${n.y}`;
      const hot = onPath?.has(n.id);
      kids.push(svg('path', { d, stroke: hot ? '#f6e016' : color, 'stroke-width': hot ? 2.4 : n.admin ? 1.8 : 1.1, fill: 'none', opacity: dim(n) ? 0.12 : hot ? 1 : n.admin ? 0.95 : 0.55, 'stroke-dasharray': n.edge === 'trust' ? '4 3' : null }));
    }
    for (const n of nodes) contact(kids, { d: shape(n.kind, n.x, n.y, n.s), x: n.x, y: n.y, s: n.s, fill: n.admin ? '#ff6b5e' : n.perms > 2000 ? '#f0b45a' : '#6fe3b0', base: dim(n) ? 0.2 : 0.95, act: null, ang: n.ang,
      sel: sel?.type === 'node' && sel.n === n,
      title: `${n.name} in ${n.account} · hop ${n.hop} · ${n.edge === 'trust' ? 'trust policy names it' : 'seen entering'} · ${num(n.perms)} permissions`, onClick: () => select({ type: 'node', n }) });
    tags(kids, nodes.filter((n) => n.admin && !dim(n)).sort((x, y) => x.hop - y.hop).map((n) => ({ ...n, text: `${short(n.name, 18)} · ${short(n.account, 16)}`, color: '#ff8a7a' })), 9);
    dial(kids, 'CAN REACH', kfmt(B.totals.perms), '#ff8a7a', `${B.totals.roles} roles · ${B.totals.accounts} accts`, '#a9bfb2');
    svgEl.replaceChildren(...kids);
  }

  function select(next) {
    sel = next && sel && ((next.type === 'node' && sel.n === next.n) || (next.type === 'account' && sel.s === next.s)) ? null : next;   // a second click closes
    drawScene();
    if (!sel) { bubble.hidden = true; return; }
    bubble.replaceChildren(...(sel.type === 'node' ? nodeBubble(sel.n) : accountBubble(sel.s)));
    bubble.hidden = false;
    place(sel.type === 'node' ? [sel.n.x, sel.n.y] : P((sel.s.a0 + sel.s.a1) / 2, 300));
  }
  // put the bubble next to the point, inside the scene, on whichever side has room
  function place([x, y]) {
    const m = svgEl.getScreenCTM(); if (!m) return;
    const pt = svgEl.createSVGPoint(); pt.x = x; pt.y = y;
    const c = pt.matrixTransform(m), box = shell.scene.getBoundingClientRect();
    const px = c.x - box.left, py = c.y - box.top, bw = bubble.offsetWidth || 300, bh = bubble.offsetHeight || 200;
    const left = px + 16 + bw > box.width - 8 ? px - 16 - bw : px + 16;
    bubble.style.left = `${Math.max(8, left)}px`;
    bubble.style.top = `${Math.min(Math.max(8, py - bh / 2), box.height - bh - 8)}px`;
  }
  const closeBtn = () => h('button', { class: 'pop-x', 'aria-label': 'Close', onClick: () => select(null) }, '×');
  const kv = (k, v) => h('div', { class: 'pop-kv' }, h('span', { class: 'tiny muted' }, k), h('span', { class: 'small' }, v));
  function nodeBubble(n) {
    const chain = chainOf(n);
    const next = nodes.filter((x) => x.parent === n.id);
    const roleKey = `role:${n.awsAccountId}:${n.name}`;
    return [
      h('div', { class: 'row pop-head' }, h('div', { class: 'stack', style: 'gap:2px;min-width:0' },
        h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: 'eyebrow' }, `HOP ${n.hop} · ROLE`), n.admin && pill('ADMIN', '#ff6b5e'), n.environment === 'production' && pill('PROD', '#ff8a7a')),
        h('b', { class: 'pop-name' }, n.name)), closeBtn()),
      kv('Account', `${n.account} · ${n.awsAccountId}${n.environment ? ` · ${n.environment}` : ''}`),
      kv('How it is reached', n.edge === 'trust' ? 'Its trust policy names the previous step (not seen used yet)' : 'Seen being entered in CloudTrail'),
      kv('Permissions', `${num(n.perms)}${n.risk ? ` · risk ${n.risk}` : ''}${n.kind ? ` · ${n.kind}` : ''}`),
      next.length > 0 && kv('Leads on to', `${next.length} more role${next.length > 1 ? 's' : ''}: ${next.slice(0, 3).map((x) => short(x.name, 28)).join(', ')}${next.length > 3 ? '…' : ''}`),
      h('div', { class: 'pop-path' }, h('span', { class: 'tiny muted' }, 'Path'),
        h('div', { class: 'small mono' }, [short(B.identity.display, 34), ...chain.map((x) => `${short(x.name, 34)} (${short(x.account, 16)})`)].join('\n→ '))),
      h('div', { class: 'row pop-actions' },
        h('a', { class: 'btn sm primary', href: `#/roles/${n.id}` }, 'Open role'),
        h('a', { class: 'btn sm', href: `#/?view=blast&key=${encodeURIComponent(roleKey)}` }, 'Blast radius from here'),
        h('a', { class: 'btn sm', href: `#/?view=account&account=${n.accountId}` }, 'Account radar')),
    ];
  }
  function accountBubble(s) {
    const L = nodes.filter((n) => n.accountId === s.id);
    return [
      h('div', { class: 'row pop-head' }, h('div', { class: 'stack', style: 'gap:2px;min-width:0' },
        h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: 'eyebrow' }, 'ACCOUNT REACHED'), s.env === 'production' && pill('PROD', '#ff8a7a')), h('b', { class: 'pop-name' }, s.name)), closeBtn()),
      kv('Roles reachable', `${L.length} · ${L.filter((n) => n.admin).length} admin-level`),
      kv('Permissions', num(L.reduce((t, n) => t + n.perms, 0))),
      h('div', { class: 'pop-list' }, L.sort((a, b) => b.perms - a.perms).slice(0, 6).map((n) => h('button', { class: 'pop-row', onClick: () => select({ type: 'node', n }) },
        h('span', { class: 'small' }, short(n.name, 36)), h('span', { class: 'tiny muted' }, `hop ${n.hop} · ${num(n.perms)}`)))),
      h('div', { class: 'row pop-actions' }, h('a', { class: 'btn sm primary', href: `#/?view=account&account=${s.id}` }, 'Open account radar')),
    ];
  }
  svgEl.addEventListener('click', () => sel && select(null));       // clicking empty space closes
  const onKey = (e) => { if (e.key === 'Escape' && sel) select(null); };
  document.addEventListener('keydown', onKey);
  const onResize = () => sel && place(sel.type === 'node' ? [sel.n.x, sel.n.y] : P((sel.s.a0 + sel.s.a1) / 2, 300));
  window.addEventListener('resize', onResize);
  ctx.onLeave?.(() => { document.removeEventListener('keydown', onKey); window.removeEventListener('resize', onResize); });
  drawScene();

  const paths = nodes.filter((n) => n.admin).sort((x, y) => x.hop - y.hop).slice(0, 6).map((n) => {
    const chain = []; let c = n; while (c) { chain.unshift(`${c.name} (${c.account})`); c = c.parent ? byId.get(c.parent) : null; }
    return { n, text: [B.identity.display, ...chain].join(' → ') };
  });
  const id = B.identity;
  shell.scene.append(svgEl, bubble,
    hudEl(`RADAR · BLAST RADIUS · ${short(id.display, 40).toUpperCase()}`,
      `${B.totals.roles} ROLES · ${B.totals.accounts} ACCOUNTS · ${B.totals.admin} ADMIN-LEVEL · ${B.totals.production} IN PRODUCTION${B.hidden ? ` · ${B.hidden} OUTSIDE YOUR SCOPE` : ''}`,
      'CENTRE = IDENTITY · RING = HOPS · SLICE = ACCOUNT REACHED · SIZE = PERMISSIONS'),
    legend([['width:16px;border-top:2px solid #6fe3b0', 'Seen entering'], ['width:16px;border-top:2px dashed #6fe3b0', 'Trust policy names it (not seen yet)'], ['width:16px;border-top:2px solid #8ec5ff', 'Role chaining'],
      ['width:10px;height:10px;border-radius:50%;background:#ff6b5e', 'Admin-level role'], ['width:10px;height:10px;border-radius:50%;background:#f0b45a', '2,000+ permissions'], ['width:16px;border-top:3px solid #7a3a30', 'Production account']]));
  shell.right.append(
    h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'IDENTITY'), h('h2', { style: 'overflow-wrap:anywhere' }, id.display),
      h('div', { class: 'tiny muted' }, `${id.kind}${id.via ? ` · ${id.via}` : ''}`)),
    h('div', { class: `cond-box${id.conditions && id.conditions.length ? '' : ' warn'}` }, h('div', { class: 'stack', style: 'gap:4px' }, h('div', { class: 'eyebrow' }, 'CONDITIONS ON ITS WAY IN'),
      h('div', { class: 'mono tiny', style: 'overflow-wrap:anywhere' }, id.conditions == null ? 'Not matched to a trust statement' : id.conditions.length ? id.conditions.join(' · ') : 'No condition in the trust policy'))),
    statGrid([['permissions reachable', kfmt(B.totals.perms), '#ff8a7a'], ['roles reachable', num(B.totals.roles), '#e3efe8'], ['accounts', num(B.totals.accounts), '#e3efe8'], ['admin-level roles', num(B.totals.admin), '#ff6b5e']]),
    B.hidden > 0 && h('p', { class: 'tiny muted' }, `${B.hidden} more role${B.hidden > 1 ? 's' : ''} in accounts outside your scope are not shown or followed.`),
    h('section', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'eyebrow' }, 'SHORTEST PATHS TO ADMIN'),
      paths.length ? paths.map((p) => { const b = h('a', { class: 'feed-item', href: `#/roles/${p.n.id}` }, h('span', { class: 'row mono tiny', style: 'justify-content:space-between' },
        h('span', { style: 'color:#ff6b5e' }, `HOP ${p.n.hop} · ADMIN`), h('span', { class: 'faint' }, `${num(p.n.perms)} perms`)), h('span', { class: 'small', style: 'overflow-wrap:anywhere;line-height:1.4' }, p.text),
        h('span', { class: 'tiny faint' }, p.n.environment === 'production' ? 'Reaches production' : p.n.environment)); b.style.borderLeftColor = '#ff6b5e'; return b; })
        : h('p', { class: 'tiny muted' }, 'No admin-level role within reach.')),
    h('p', { class: 'tiny faint', style: 'line-height:1.5' }, 'Reach is what the trust policies allow and what was seen. It does not yet check whether each role holds sts:AssumeRole on the next one, so a dashed edge is a possibility, not a proven path.'));
}

function statGrid(items) {
  return h('div', { class: 'stat-grid' }, items.map(([k, v, c]) => h('div', null, h('span', { class: 'mono', style: `color:${c};font-size:17px` }, v), h('span', { class: 'tiny muted' }, k))));
}
function pill(text, color) { const s = h('span', { class: 'pill' }, text); s.style.color = color; s.style.borderColor = color; return s; }
