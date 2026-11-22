// Networking at the size of a real estate (src/network/demoLarge.js: a central network account sharing 38 VPCs with
// eleven app accounts, two transit gateways, 36 VPNs, Direct Connect, twenty peerings to accounts not connected, ~1,900
// network interfaces): the analyzer and the page's API stay quick, and Space and the Map lay it out with nothing on
// top of anything else.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.DATABASE_URL = 'postgres://cm:cm@127.0.0.1:54395/cm';
const { analyzeNetwork } = await import('../src/network/analyze.js');
const { LARGE_ESTATE, LARGE_HUB, largeEstateItems, largeAwsNetwork } = await import('../src/network/demoLarge.js');
const { spaceLayout, packZones, placeLabels, CELL_W, AISLE, GAP } = await import('../public/js/pages/netSpaceLayout.js');
const { mapLayout } = await import('../public/js/pages/netMapLayout.js');

const estate = { awsAccounts: new Map(LARGE_ESTATE.map(([id, name]) => [id, { name }])) };
const owners = LARGE_ESTATE.map(([id, name, environment]) => ({ cloud: 'aws', owner: id, name, environment }));
const overlap = (a, b, pad = 0) => a.x0 < b.x1 + pad && b.x0 < a.x1 + pad && a.y0 < b.y1 + pad && b.y0 < a.y1 + pad;
const disc = (p) => ({ x0: p.x - p.r, x1: p.x + p.r, y0: p.y - p.r, y1: p.y + p.r });

// ---------------------------------------------------------------- no database
let analysed;
test('the large estate: hundreds of resources, analysed in well under a second', () => {
  const items = largeEstateItems();
  assert.ok(items.length > 2500, `${items.length} items`);
  assert.ok(items.filter((i) => i.type === 'eni').length > 1500);
  const t = Date.now();
  analysed = analyzeNetwork(items, estate);
  assert.ok(Date.now() - t < 2000, `analysed in ${Date.now() - t} ms`);
  const kinds = (k, stub = false) => analysed.graph.nodes.filter((n) => n.kind === k && !!n.stub === stub).length;
  assert.equal(kinds('vpc'), 49, 'the network account\'s 38 and eleven default VPCs');
  assert.equal(kinds('vpc', true), 20, 'the partners\' VPCs, not connected');
  assert.ok(kinds('slice') >= 30, 'the app accounts\' parts of the shared VPCs');
  assert.ok(kinds('peer') >= 36, 'a customer gateway for each VPN');
  assert.equal(kinds('tgw'), 2);
  assert.equal(analysed.graph.links.filter((l) => l.kind === 'vpn').length, 36);
  // the same thing is the same ID whichever account read it, and every account's read is the same twice
  assert.deepEqual(largeAwsNetwork(LARGE_HUB, 'ap-southeast-3').map((i) => i.id), largeAwsNetwork(LARGE_HUB, 'ap-southeast-3').map((i) => i.id));
  // the mistakes in it are found
  const titles = analysed.findings.map((f) => f.title);
  assert.ok(titles.some((x) => /redteam-listener/.test(x) && /every port|all traffic/i.test(x)) || analysed.findings.some((f) => f.control === 'net.sg-all-open'));
  assert.ok(analysed.exposures.some((e) => /legacy-portal \(Classic Load Balancer\)/.test(e.name)));
  assert.ok(analysed.findings.filter((f) => f.control === 'net.vpn-down').length >= 5);
});

test('Space: zones packed without overlapping, rings inside them, peers in front, hubs in the aisle', () => {
  const d = { nodes: analysed.graph.nodes, links: analysed.graph.links, owners };
  const L = spaceLayout(d);
  assert.equal(L.zones.length, LARGE_ESTATE.length);
  for (let i = 0; i < L.zones.length; i++) for (let j = i + 1; j < L.zones.length; j++) assert.ok(!overlap(L.zones[i], L.zones[j], GAP - 1), `${L.zones[i].owner.name} / ${L.zones[j].owner.name}`);
  // every ring in its own zone, none on another
  const rings = d.nodes.filter((n) => !n.stub && ['vpc', 'slice'].includes(n.kind));
  for (const n of rings) {
    const p = L.P.get(n.id), z = L.zones.find((x) => x.owner.owner === n.owner);
    assert.ok(p.x - p.r >= z.x0 && p.x + p.r <= z.x1 && p.y - p.r >= z.y0 && p.y + p.r <= z.y1, n.label);
  }
  for (let i = 0; i < rings.length; i++) for (let j = i + 1; j < rings.length; j++) assert.ok(!overlap(disc(L.P.get(rings[i].id)), disc(L.P.get(rings[j].id))), `${rings[i].label} / ${rings[j].label}`);
  // everything else has a place: hubs in the aisle apart from each other, peers and outsiders in front of the zones
  const hubs = d.nodes.filter((n) => ['tgw', 'dxgw'].includes(n.kind)), outs = d.nodes.filter((n) => n.kind === 'peer' || (n.stub && !['tgw', 'dxgw'].includes(n.kind)));
  for (const n of [...hubs, ...outs]) assert.ok(L.P.has(n.id), n.label);
  for (const n of hubs) assert.ok(Math.abs(L.P.get(n.id).x) < AISLE, n.label);
  for (let i = 0; i < hubs.length; i++) for (let j = i + 1; j < hubs.length; j++) assert.ok(Math.abs(L.P.get(hubs[i].id).y - L.P.get(hubs[j].id).y) >= 149);
  const front = Math.min(...L.zones.map((z) => z.y0));
  for (const n of outs) assert.ok(L.P.get(n.id).y + L.P.get(n.id).r < front, n.label);
  for (let i = 0; i < outs.length; i++) for (let j = i + 1; j < outs.length; j++) assert.ok(!overlap(disc(L.P.get(outs[i].id)), disc(L.P.get(outs[j].id)), 40), `${outs[i].label} / ${outs[j].label}`);
  // a transit gateway's VPN peers together, in name order along the rows
  const vpnPeers = d.links.filter((l) => l.kind === 'vpn').map((l) => (l.from.startsWith('aws:tgw') ? l.to : l.from));
  const xs = vpnPeers.map((id) => L.P.get(id).x), spread = Math.max(...xs) - Math.min(...xs);
  assert.ok(spread <= 12 * 200, `VPN peers ${spread} wide`);   // one block, twelve across
  // and the band in front stays shallow: a few rows, spread across the width of the zones
  assert.ok(Math.min(...outs.map((n) => L.P.get(n.id).y)) >= -6 * 180, 'no more than six rows of outsiders');
  // wider than deep, not a tower: the whole scene about as wide as a screen is
  const w = L.bounds.x1 - L.bounds.x0, h = L.bounds.y1 - L.bounds.y0;
  assert.ok(w / h > 0.9 && w / h < 4, `${Math.round(w)} × ${Math.round(h)}`);
});

test('Space: zones packed in shelves, a small one stacking behind another beside a deep one', () => {
  const zs = [{ w: 600, d: 400 }, { w: 300, d: 150 }, { w: 300, d: 150 }, { w: 300, d: 300 }];
  const r = packZones(zs, 1000);
  // beside the first; behind that one (both fit the first's depth); a new shelf behind them all
  assert.deepEqual(zs.map((z) => [z.u, z.v]), [[0, 0], [600 + GAP, 0], [600 + GAP, 150 + GAP], [0, 400 + GAP]]);
  assert.deepEqual(r, { width: 600 + GAP + 300, depth: 400 + GAP + 300 });
  assert.ok(CELL_W >= 2 * 84, 'a cell holds the largest ring');
});

test('labels: the most important first, none on top of another, a second line only under its first', () => {
  const kept = placeLabels([
    { x: 0, y: 0, w: 100, h: 14, prio: 1 },     // 0: loses to 1
    { x: 50, y: 5, w: 100, h: 14, prio: 5 },    // 1
    { x: 200, y: 0, w: 50, h: 14, prio: 1 },    // 2: alone
    { x: 210, y: 400, w: 50, h: 12, prio: 0, needs: 0 },   // 3: its first line was not kept
    { x: 2000, y: 0, w: 50, h: 12, prio: 9 },   // 4: off the stage
  ], { view: { w: 1400, h: 820 } });
  assert.deepEqual([...kept].sort(), [1, 2]);
  // a label whose place is taken goes to the first other place that is free
  const list = [{ x: 0, y: 100, w: 100, h: 14, prio: 5 }, { x: 60, y: 100, w: 100, h: 14, prio: 1, alts: [{ x: 60, y: 104 }, { x: 60, y: 60 }] }];
  assert.deepEqual([...placeLabels(list)].sort(), [0, 1]);
  assert.deepEqual([list[0].at, list[1].at], [{ x: 0, y: 100 }, { x: 60, y: 60 }]);
});

test('the Map: cards side by side, boxes inside them, the middle in columns as tall as the clouds', () => {
  const d = { nodes: analysed.graph.nodes, links: analysed.graph.links, owners };
  const L = mapLayout(d);
  const rect = (p) => ({ x0: p.x, x1: p.x + p.w, y0: p.y, y1: p.y + p.h });
  for (let i = 0; i < L.cards.length; i++) for (let j = i + 1; j < L.cards.length; j++) assert.ok(!overlap(rect(L.cards[i]), rect(L.cards[j])), `${L.cards[i].owner.name} / ${L.cards[j].owner.name}`);
  const boxes = [...L.pos.entries()];
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) assert.ok(!overlap(rect(boxes[i][1]), rect(boxes[j][1])), `${boxes[i][0]} / ${boxes[j][0]}`);
  for (const c of L.cards) for (const n of c.list) { const b = rect(L.pos.get(n.id)); assert.ok(b.x0 >= c.x && b.x1 <= c.x + c.w && b.y0 >= c.y && b.y1 <= c.y + c.h, n.label); }
  // not a strip many times taller than wide
  assert.ok(L.height < L.width * 1.3, `${L.width} × ${L.height}`);
});

// ---------------------------------------------------------------- with the database
let pg, db, sync, api;
before(async () => {
  pg = await startPg(54395);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  sync = await import('../src/network/sync.js'); api = await import('../src/network/api.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','x')`);
  for (const [id, name, env] of LARGE_ESTATE) {
    const a = (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ($1,$2,$3,'arn:aws:iam::${id}:role/cm','{ap-southeast-3}','connected') RETURNING id`, [id, name, env])).rows[0];
    await sync.saveNetwork({ cloud: 'aws', owner: id, accountId: a.id, items: largeAwsNetwork(id, 'ap-southeast-3'), skipped: [] });
  }
});
after(async () => { await db?.closePool(); await pg?.stop(); });

test('the page\'s API on the large estate: quick, everything in it, a transit gateway\'s attachments by name', async () => {
  const owner = { id: null, scope_accounts: null };
  let t = Date.now();
  const filed = await sync.analyzeAndFile();
  assert.ok(Date.now() - t < 5000, `filed in ${Date.now() - t} ms`);
  assert.ok(filed.findings.length > 80);
  t = Date.now();
  const o = await api.networkOverview(owner);
  assert.ok(Date.now() - t < 5000, `overview in ${Date.now() - t} ms`);
  assert.equal(o.owners.length, LARGE_ESTATE.length);
  assert.ok(o.nodes.length >= 140 && o.links.length >= 150, `${o.nodes.length} nodes, ${o.links.length} lines`);
  // the layouts hold on what the page gets
  const L = spaceLayout(o);
  for (const n of o.nodes) if (n.id !== 'internet') assert.ok(L.P.has(n.id) || n.kind === 'internet', n.label);
  assert.ok(mapLayout(o).cards.length === LARGE_ESTATE.length);
  // the core transit gateway: 65 attachments, VPCs first, by name, each VPC one click away
  const tgw = o.nodes.find((n) => n.kind === 'tgw' && n.label === 'acme-core-tgw');
  const x = await api.networkDetail(owner, tgw.id);
  assert.ok(x.attachments.length > 60);
  assert.equal(x.attachments[0].resourceType, 'vpc');
  assert.ok(x.attachments.filter((a) => a.resourceType === 'vpc').every((a) => a.resourceName && a.node && a.ownerName === 'acme-network-hub'));
  const vpcs = x.attachments.filter((a) => a.resourceType === 'vpc').map((a) => a.resourceName);
  assert.deepEqual(vpcs, [...vpcs].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })));
  // the inventory names each account, and finds by its name
  const inv = await api.networkInventory(owner, { q: 'acme-research', type: 'eni' });
  assert.ok(inv.total > 0 && inv.items.every((i) => i.ownerName === 'acme-research' || i.owner === LARGE_HUB), `${inv.total} found`);
  // a member limited to one app account sees its own zone and, of the network account's, only the VPCs it runs in
  const scoped = { id: null, scope_accounts: [(await db.query(`SELECT id FROM cloud_accounts WHERE name = 'acme-payments'`)).rows[0].id] };
  const so = await api.networkOverview(scoped);
  assert.deepEqual(so.owners.map((x) => x.name).sort(), ['acme-network-hub', 'acme-payments']);
  assert.deepEqual(so.nodes.filter((n) => n.kind === 'vpc' && n.owner === LARGE_HUB).map((n) => n.label).sort(), ['hub-prd-apse1', 'hub-prd-apse3', 'payments-dr-apse1', 'payments-prd-apse3']);
  assert.ok(spaceLayout(so).zones.length === 2);
});
