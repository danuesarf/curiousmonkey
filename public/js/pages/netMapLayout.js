// Networking → Map: where the boxes go, apart from drawing them, so it can be tested on an estate of hundreds of VPCs
// and peers (test/networkLarge.test.js). AWS accounts on the left, Google Cloud projects on the right, each a card
// of its VPCs or networks (more to a row the more it has); between them the internet, hubs, peers and networks outside
// the estate, in as many columns as keep them about as tall as the clouds beside them.

export const NW = 252, NH = 94, PAD = 14, HEAD = 40, GAP = 44, BOX_GAP = 16, ROW_GAP = 14, CARD_GAP = 22, MID = 250, MID_H = 76, MID_STEP = 94, TOP = 110;
const isRing = (n) => !n.stub && (n.kind === 'vpc' || n.kind === 'network' || n.kind === 'slice');
const hubish = (n) => ['tgw', 'dxgw', 'hub'].includes(n.kind);

/** Cards in rows across a column `width` wide, the next row under the deepest card of the one before. */
function shelve(cards, width) {
  let x = 0, y = 0, rowH = 0;
  for (const c of cards) {
    if (x > 0 && x + c.w > width) { x = 0; y += rowH + CARD_GAP; rowH = 0; }
    c.dx = x; c.dy = y; x += c.w + CARD_GAP; rowH = Math.max(rowH, c.h);
  }
  return y + rowH;
}

/**
 * The map's layout from the overview (/api/network): `cloud` '' (both), 'aws' or 'gcp'; `internet` whether the
 * internet is drawn; `rank(node)` orders a card's boxes. Returns pos (node id -> { x, y, w, h }), cards, the columns'
 * places (xMid, midW, xGcp) and the map's width and height.
 */
export function mapLayout(d, { cloud = '', internet = true, rank = () => 0 } = {}) {
  const pos = new Map(), cards = [];
  const shown = (n) => !cloud || !n.cloud || n.cloud === cloud || n.kind === 'peer';
  const byOwner = new Map();
  for (const n of d.nodes || []) if (n.cloud && isRing(n)) { const k = `${n.cloud}|${n.owner}`; (byOwner.get(k) || byOwner.set(k, []).get(k)).push(n); }
  // a card per account or project: its own VPCs or networks, then its parts of VPCs others share with it, default last
  const cardsOf = (c) => (d.owners || []).filter((o) => o.cloud === c && (!cloud || cloud === c) && byOwner.has(`${c}|${o.owner}`)).map((o) => {
    const list = byOwner.get(`${c}|${o.owner}`).slice().sort((a, b) => (a.kind === 'slice' ? 1 : 0) - (b.kind === 'slice' ? 1 : 0) || (a.isDefault ? 1 : 0) - (b.isDefault ? 1 : 0)
      || rank(a) - rank(b) || String(a.label).localeCompare(String(b.label), undefined, { numeric: true }));
    const cols = list.length < 2 ? 1 : Math.max(2, Math.min(6, Math.ceil(Math.sqrt(list.length / 1.2)))), rows = Math.ceil(list.length / cols);
    return { owner: o, list, cols, w: 2 * PAD + cols * NW + (cols - 1) * BOX_GAP, h: HEAD + rows * (NH + ROW_GAP) - ROW_GAP + 2 * PAD };
  }).sort((a, b) => b.list.length - a.list.length || String(a.owner.name).localeCompare(String(b.owner.name)));
  const col = (list) => {
    if (!list.length) return { w: 0, h: 0 };
    const area = list.reduce((s, c) => s + (c.w + CARD_GAP) * (c.h + CARD_GAP), 0), w = Math.max(2 * PAD + 2 * NW + BOX_GAP, ...list.map((c) => c.w), Math.sqrt(area * 1.4));
    const h = shelve(list, w);
    return { w: Math.max(...list.map((c) => c.dx + c.w)), h };
  };
  const aws = cardsOf('aws'), gcp = cardsOf('gcp'), A = col(aws), G = col(gcp);
  // the middle: the internet on top, then hubs, then peers and outside networks, in columns about as tall as the clouds
  const mid = (d.nodes || []).filter((n) => shown(n) && (hubish(n) || n.kind === 'peer' || n.stub))
    .sort((a, b) => (hubish(a) ? 0 : 1) - (hubish(b) ? 0 : 1) || (a.kind === 'peer' ? 0 : 1) - (b.kind === 'peer' ? 0 : 1) || String(a.label).localeCompare(String(b.label), undefined, { numeric: true }));
  const rowsWanted = Math.max(6, Math.floor(Math.max(A.h, G.h, 0) / MID_STEP));
  const midCols = Math.max(1, Math.min(8, Math.ceil(mid.length / rowsWanted))), midW = midCols * MID + (midCols - 1) * BOX_GAP;
  const xMid = (A.w || 0) + (A.w ? GAP : 0), xGcp = xMid + midW + GAP;
  for (const c of aws) cards.push({ x: c.dx, y: TOP + c.dy, w: c.w, h: c.h, owner: c.owner, list: c.list, cols: c.cols });
  for (const c of gcp) cards.push({ x: xGcp + c.dx, y: TOP + c.dy, w: c.w, h: c.h, owner: c.owner, list: c.list, cols: c.cols });
  for (const c of cards) c.list.forEach((n, i) => pos.set(n.id, { x: c.x + PAD + (i % c.cols) * (NW + BOX_GAP), y: c.y + HEAD + Math.floor(i / c.cols) * (NH + ROW_GAP), w: NW, h: NH }));
  if (internet && (d.nodes || []).some((n) => n.kind === 'internet')) pos.set('internet', { x: xMid + midW / 2 - (MID - 50) / 2, y: 4, w: MID - 50, h: 52 });
  mid.forEach((n, i) => pos.set(n.id, { x: xMid + (i % midCols) * (MID + BOX_GAP), y: TOP + Math.floor(i / midCols) * MID_STEP, w: MID, h: MID_H }));
  const midH = Math.ceil(mid.length / midCols) * MID_STEP;
  return { pos, cards, xMid, midW, xGcp, width: xGcp + (G.w || 0), height: TOP + Math.max(A.h, G.h, midH) + 20 };
}
