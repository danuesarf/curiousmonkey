// The Networking page's data: the map (nodes, links, exposure), findings, the inventory and one VPC or network in
// detail. Worked out from what is stored (src/network/sync.js) on each request, cached briefly. A member limited
// to some AWS accounts sees those accounts' networks only, and no Google Cloud, as everywhere else.
import { query } from '../db.js';
import { cached, scopeKey } from '../cache.js';
import { analyzeNetwork, ADMIN_PORTS, DATA_PORTS } from './analyze.js';
import { loadItems, networkEstate, pendingNetworkRead } from './sync.js';
import { loadUsage, loadHours, flowState, flowStorage, flowStep, LOOKBACK_DAYS, KEEP_DAYS } from './flows.js';
import { loadPolicy } from '../controls.js';
import { environmentOf } from '../environments.js';

export class NetError extends Error { constructor(status, message) { super(message); this.status = status; } }
const SEV = { high: 0, medium: 1, low: 2, none: 3 };

// the 24 one-hour buckets ending with the current hour (`day` days back), as Space replays them
const hourStart = (day = 0) => Math.floor(Date.now() / 36e5) * 36e5 - 23 * 36e5 - day * 864e5;
async function model() {
  return cached('network:model', async () => {
    const start = hourStart();
    const [items, estate, policy, accts, projects, usage, flowReads, flowBytes] = await Promise.all([loadItems(), networkEstate(), loadPolicy(),
      query('SELECT id, account_id, name, environment FROM cloud_accounts').then((r) => r.rows),
      query('SELECT DISTINCT ON (project_id) project_id, name, environment, connection_id FROM gcp_projects ORDER BY project_id').then((r) => r.rows).catch(() => []),
      loadUsage({ hourStart: start }), query('SELECT * FROM net_flow_reads').then((r) => r.rows).catch(() => []), flowStorage().catch(() => null)]);
    const r = analyzeNetwork(items, estate, policy, usage);
    // r.items: what was read with shared VPCs merged (one VPC under its owner, each interface once)
    return { ...r, accts, projects, hourStart: start, flowReads: new Map(flowReads.map((x) => [x.flow_log, x])), flowBytes, targetOf: targets(r.graph, r.items, r.vpcOwnerOf) };
  }, { freshMs: 30e3, staleMs: 120e3 });
}
/** Every active AWS flow log in what was read, with whether and how far it is read (src/network/flows.js). */
function flowLogsOf(m, pick = () => true) {
  const now = Date.now();
  return m.items.filter((i) => i.cloud === 'aws' && i.type === 'flow-log' && i.data.status === 'ACTIVE' && pick(i)).map((i) => {
    const r = m.flowReads.get(i.id);
    return { flowLog: i.id, owner: i.owner, resource: i.data.resource, vpcNode: r?.vpc_node || (i.vpc ? `aws:vpc:${i.vpcOwner || i.owner}:${i.vpc}` : null), traffic: i.data.traffic,
      destination: i.data.destination, arn: i.data.arn, bucket: r?.bucket || null, prefix: r?.prefix ?? null, ...flowState(i, r, now) };
  }).sort((a, b) => String(a.vpcNode).localeCompare(String(b.vpcNode)) || a.flowLog.localeCompare(b.flowLog));
}

/**
 * Where on the map a finding is: the line it is about (a VPN, an unused peering, a PrivateLink service shared
 * outside), else the box (a VPC, a network, a transit gateway, a Direct Connect gateway), else null.
 */
function targets(graph, items, vpcOwnerOf = (o) => o) {
  const links = new Set(graph.links.map((l) => l.id));
  const nodeByNative = new Map(); for (const n of graph.nodes) if (n.nativeId && !nodeByNative.has(n.nativeId)) nodeByNative.set(n.nativeId, n.id);
  // a line by what it is built from: its own ID, an AWS VPN connection on it, a Google Cloud tunnel on it
  const linkBy = new Map();
  const put = (k, l) => { if (k && (!linkBy.has(k) || (l.outside && !linkBy.get(k).outside))) linkBy.set(k, l); };
  for (const l of graph.links) {
    put(l.nativeId, l);
    for (const v of l.vpns || []) put(v.id, l);
    for (const t of l.tunnels || []) if (t.gcp) put(`tunnel:${t.gcp}`, l);
  }
  const tgwOfTable = new Map(items.filter((i) => i.type === 'tgw-route-table').map((i) => [i.id, i.data.tgw]));
  return (f) => {
    const native = f.native_id ?? f.nativeId, type = f.item_type ?? f.itemType;
    if (links.has(native)) return native;
    const l = linkBy.get(native) || (type === 'vpn-tunnel' ? linkBy.get(`tunnel:${String(native).split('/').pop()}`) : null);
    if (l && !f.vpc) return l.id;
    if (type === 'tgw-route-table' && tgwOfTable.get(native)) return `aws:tgw:${tgwOfTable.get(native)}`;
    if (f.vpc) return f.cloud === 'aws' ? `aws:vpc:${vpcOwnerOf(f.owner, f.vpc)}:${f.vpc}` : `gcp:net:${f.vpc}`;
    return nodeByNative.get(native) || null;
  };
}

/**
 * Which owners this person may see: everything when not limited; else the AWS accounts in scope, and no Google Cloud.
 * A shared VPC is seen by whoever may see its owner or one of the accounts running something in it (`node`), but
 * what other accounts run there stays theirs (`full`).
 */
function visible(user, m) {
  const scoped = !!user.scope_accounts;
  const aws = new Set(m.accts.filter((a) => !scoped || user.scope_accounts.includes(a.id)).map((a) => a.account_id));
  const ok = (cloud, owner) => (!scoped ? true : cloud === 'aws' ? aws.has(owner) : cloud === 'gcp' ? false : true);
  return { aws, gcp: !scoped, scoped, ok, node: (n) => !n.cloud || ok(n.cloud, n.owner) || (n.tenants || []).some((t) => ok('aws', t.account)), full: (n) => !n.cloud || ok(n.cloud, n.owner) };
}

// a shared VPC seen through an account that runs something in it: the VPC, and only that account's part of it
const sum = (list, k) => list.reduce((a, y) => a + (y[k] || 0), 0);
function participantView(n, v) {
  if (v.full(n)) return n;
  const mine = (n.tenants || []).filter((y) => v.ok('aws', y.account));
  return { ...n, participantView: true, findings: 0, worst: 'none', exposed: sum(mine, 'exposed'), interfaces: sum(mine, 'interfaces'),
    tenants: (n.tenants || []).map((y) => (v.ok('aws', y.account) ? y : { account: y.account, name: y.name, owner: y.owner, read: y.read, hidden: true })) };
}

// a node is drawn when it is visible, or is the other end of a link from one that is
function shownOf(m, v) {
  const shown = new Set(m.graph.nodes.filter((n) => n.cloud && v.node(n) && !n.stub).map((n) => n.id));
  const links = m.graph.links.filter((l) => shown.has(l.from) || shown.has(l.to));
  for (const l of links) { shown.add(l.from); shown.add(l.to); }
  return { shown, links };
}

export async function networkOverview(user) {
  const m = await model(), v = visible(user, m);
  const reads = (await query('SELECT * FROM net_reads ORDER BY cloud, owner')).rows.filter((r) => v.ok(r.cloud, r.owner));
  const { shown, links } = shownOf(m, v);
  const partOf = (n) => participantView(n, v);
  // the far end of a link into something this person may not see: its name and owner only
  const nodes = m.graph.nodes.filter((n) => shown.has(n.id)).map((n) => (v.full(n) ? n : v.node(n) ? partOf(n)
    : { id: n.id, kind: n.kind, cloud: n.cloud, owner: n.owner, nativeId: n.nativeId, label: n.label, ownerName: n.ownerName, yours: n.yours, read: false, stub: true, hidden: true, cidrs: [], worst: 'none', findings: 0 }));
  const env = new Map([...m.accts.map((a) => [`aws|${a.account_id}`, { name: a.name, environment: environmentOf(a.environment), id: a.id }]),
    ...m.projects.map((p) => [`gcp|${p.project_id}`, { name: p.project_id, title: p.name, environment: environmentOf(p.environment) }])]);
  for (const n of nodes) { const e = env.get(`${n.cloud}|${n.owner}`); n.environment = e?.environment || null; n.ownerLabel = e?.name || n.ownerName || n.owner; n.accountId = e?.id || null; }
  const open = (await query(`SELECT id, control, severity, title, cloud, owner, item_type, native_id, vpc FROM net_findings WHERE status = 'open' AND decision IS DISTINCT FROM 'expected'
    ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, title`)).rows.filter((r) => v.ok(r.cloud, r.owner));
  const sev = { high: 0, medium: 0, low: 0 }; for (const c of open) sev[c.severity]++;
  // what is open on each line, for its panel (boxes fetch theirs with the detail)
  const linkIds = new Set(links.map((l) => l.id)), onLinks = {};
  for (const r of open) { const t = m.targetOf(r); if (linkIds.has(t)) (onLinks[t] ||= []).push({ id: r.id, control: r.control, severity: r.severity, title: r.title }); }
  const owners = [...new Set(nodes.filter((n) => n.cloud && !n.stub).map((n) => `${n.cloud}|${n.owner}`))].map((k) => { const [cloud, owner] = k.split('|'); const e = env.get(k); return { cloud, owner, name: e?.name || owner, title: e?.title || null, environment: e?.environment || null, accountId: e?.id || null }; });
  return {
    reads: reads.map((r) => ({ cloud: r.cloud, owner: r.owner, name: env.get(`${r.cloud}|${r.owner}`)?.name || r.owner, readAt: r.read_at, skipped: r.skipped, error: r.error, counts: r.counts })),
    owners, nodes, links, exposures: m.exposures.filter((e) => v.ok(e.cloud, e.owner)).sort((a, b) => SEV[a.severity] - SEV[b.severity]),
    findings: sev, linkFindings: onLinks, pending: await pendingNetworkRead(), ports: { admin: ADMIN_PORTS, data: DATA_PORTS }, hourStart: new Date(m.hourStart).toISOString(),
    flowLogs: flowLogsOf(m, (i) => v.ok('aws', i.owner)),
    flow: { lookbackDays: LOOKBACK_DAYS, keepDays: KEEP_DAYS, storedBytes: m.flowBytes, step: await flowStep().catch(() => null) },
  };
}

/**
 * The lines' traffic by the hour for the 24 hours `day` days before the last 24 (0: the last 24 hours), for Space to
 * replay an earlier day: { hourStart, day, hours: { link id: [24 × { bytes, rejected }] } }, the lines this person sees.
 */
export async function networkHours(user, { day = 0 } = {}) {
  const m = await model(), v = visible(user, m);
  const d = Math.max(0, Math.min(LOOKBACK_DAYS - 1, Math.floor(Number(day) || 0))), start = hourStart(d);
  const ids = new Set(shownOf(m, v).links.map((l) => l.id));
  const all = await cached(`network:hours:${start}`, () => loadHours(start), { freshMs: 60e3, staleMs: 300e3 });
  return { day: d, hourStart: new Date(start).toISOString(), hours: Object.fromEntries([...all].filter(([id]) => ids.has(id))) };
}

export async function networkFindings(user, q = {}) {
  const m = await model(), v = visible(user, m);
  const p = [], where = [];
  const add = (sql, val) => { p.push(val); where.push(sql.replace('?', `$${p.length}`)); };
  add('f.status = ?', q.status === 'resolved' ? 'resolved' : 'open');
  if (q.severity) add('f.severity = ANY(?)', String(q.severity).split(',').filter((x) => SEV[x] != null));
  if (q.cloud === 'aws' || q.cloud === 'gcp') add('f.cloud = ?', q.cloud);
  if (q.control) add('f.control = ?', String(q.control));
  if (q.owner) add('f.owner = ?', String(q.owner));
  if (q.vpc) add('f.vpc = ?', String(q.vpc));
  // a member limited to some accounts: only those, before the limit, so the list is not cut short by rows they cannot see
  if (user.scope_accounts) add(`f.cloud = 'aws' AND f.owner = ANY(?)`, [...v.aws]);
  const names = new Map([...m.accts.map((a) => [`aws|${a.account_id}`, a.name]), ...m.projects.map((x) => [`gcp|${x.project_id}`, x.project_id])]);
  if (q.q) {
    // the account's name finds its findings too, as the list shows names, not numbers
    const text = String(q.q).toLowerCase(), owners = [...names].filter(([, n]) => String(n).toLowerCase().includes(text)).map(([k]) => k.split('|')[1]);
    p.push(`%${String(q.q).replace(/[%_\\]/g, '\\$&')}%`, owners);
    where.push(`((f.title || ' ' || f.detail || ' ' || f.control || ' ' || coalesce(f.item_name, '') || ' ' || coalesce(f.native_id, '') || ' ' || f.owner) ILIKE $${p.length - 1} OR f.owner = ANY($${p.length}))`);
  }
  const rows = (await query(`SELECT f.*, u.name AS decided_by_name FROM net_findings f LEFT JOIN users u ON u.id = f.decided_by WHERE ${where.join(' AND ')}
    ORDER BY CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, f.decision NULLS FIRST, f.updated_at DESC LIMIT 1000`, p)).rows.filter((r) => v.ok(r.cloud, r.owner));
  return { items: rows.map((r) => ({ id: r.id, control: r.control, severity: r.severity, cloud: r.cloud, owner: r.owner, ownerName: names.get(`${r.cloud}|${r.owner}`) || r.owner, itemType: r.item_type, target: m.targetOf(r),
    nativeId: r.native_id, itemName: r.item_name, vpc: r.vpc, title: r.title, detail: r.detail, suggestion: r.suggestion, status: r.status, decision: r.decision, note: r.note,
    decidedBy: r.decided_by_name, decidedAt: r.decided_at, openedAt: r.created_at, resolvedAt: r.resolved_at })) };
}

// what an account or project runs in a VPC or network (the rest of it is the owner's)
const RESOURCE = new Set(['eni', 'sg', 'lb', 'endpoint', 'client-vpn', 'resolver-endpoint', 'instance', 'forwarding-rule', 'psc-endpoint', 'ilb']);
/** One VPC (AWS) or network (Google Cloud), with everything in it; or a member account's part of a shared VPC. */
export async function networkDetail(user, nodeId) {
  const m = await model(), v = visible(user, m);
  const asked = m.graph.nodes.find((x) => x.id === nodeId);
  if (!asked || (asked.cloud && !v.node(asked))) throw new NetError(404, 'Not found.');
  // a member's slice of a shared VPC (or a service project's of a Shared VPC network): the VPC, with its part only
  const n = asked.kind === 'slice' ? m.graph.nodes.find((x) => x.id === (asked.cloud === 'gcp' ? `gcp:net:${asked.nativeId}` : `aws:vpc:${asked.vpcOwner}:${asked.nativeId}`)) : asked;
  if (!n) throw new NetError(404, 'Not found.');
  const only = asked.kind === 'slice' ? asked.owner : null;
  // in a VPC: its structure (subnets, route tables, gateways, ACLs) is the owner's; resources belong to whoever runs
  // them, and someone limited to some accounts sees only theirs
  const mine = (i) => i.cloud === n.cloud && (i.vpcOwner || i.owner) === n.owner && i.vpc === n.nativeId
    && (!RESOURCE.has(i.type) || ((!only || i.owner === only) && v.ok(i.cloud, i.owner)));
  const list = (type) => m.items.filter((i) => i.type === type && mine(i));
  const ends = new Set([asked.id, n.id]);
  const links = m.graph.links.filter((l) => ends.has(l.from) || ends.has(l.to)).map((l) => ({ ...l, other: m.graph.nodes.find((x) => x.id === (ends.has(l.from) ? l.to : l.from)) }));
  // what is open on this box: in it (whoever runs it), or about it (a transit gateway's route table, a Direct Connect gateway)
  const inIt = (r) => r.vpc === n.nativeId && m.vpcOwnerOf(r.owner, r.vpc) === n.owner && (!only || r.owner === only);
  const findings = (await query(`SELECT id, control, severity, title, detail, suggestion, item_name, item_type, native_id, vpc, cloud, owner, decision FROM net_findings WHERE status = 'open' AND cloud = $1
    ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END`, [n.cloud || ''])).rows
    .filter((r) => v.ok(r.cloud, r.owner) && (inIt(r) || (!only && ((r.owner === n.owner && r.native_id === n.nativeId) || m.targetOf(r) === n.id))))
    .map(({ native_id: _n, vpc: _v, cloud: _c, ...r }) => r);
  const base = { node: only ? { ...n, ...asked } : participantView(n, v), vpcNode: only ? n.id : null, tenants: participantView(n, v).tenants || null, links, findings,
    exposures: m.exposures.filter((e) => e.cloud === n.cloud && (e.vpcOwner || e.owner) === n.owner && e.vpc === n.nativeId && v.ok(e.cloud, e.owner) && (!only || e.owner === only)) };
  if (n.kind === 'vpc' && !n.stub) {
    const rts = list('route-table'), subnets = list('subnet');
    const tableOf = (s) => rts.find((t) => t.data.subnets.includes(s.id)) || rts.find((t) => t.data.main);
    const enis = list('eni'), groupUse = new Map();
    for (const e of enis) for (const g of e.data.groups) groupUse.set(g, (groupUse.get(g) || 0) + 1);
    return { ...base,
      subnets: subnets.map((s) => { const t = tableOf(s); return { id: s.id, name: s.name, cidr: s.data.cidr, az: s.data.az, mapPublicIp: s.data.mapPublicIp, routeTable: t?.id || null,
        public: !!t?.data.routes.some((r) => (r.dest === '0.0.0.0/0' || r.dest === '::/0') && r.target.type === 'igw'), interfaces: enis.filter((e) => e.data.subnet === s.id).length }; }).sort((a, b) => String(a.cidr).localeCompare(String(b.cidr), undefined, { numeric: true })),
      routeTables: rts.map((t) => ({ id: t.id, name: t.name, main: t.data.main, subnets: t.data.subnets, routes: t.data.routes })),
      securityGroups: list('sg').map((g) => ({ id: g.id, account: g.owner, name: g.name, description: g.data.description, isDefault: g.data.isDefault, ingress: g.data.ingress, egress: g.data.egress, used: groupUse.get(g.id) || 0 })),
      nacls: list('nacl').map((a) => ({ id: a.id, name: a.name, isDefault: a.data.isDefault, subnets: a.data.subnets, entries: a.data.entries })),
      gateways: [...list('igw'), ...list('eigw'), ...list('nat'), ...list('vgw'), ...m.items.filter((i) => i.cloud === 'aws' && i.owner === n.owner && i.type === 'igw' && i.data.vpcs?.includes(n.nativeId) && i.vpc !== n.nativeId)]
        .map((g) => ({ type: g.type, id: g.id, name: g.name, detail: g.type === 'nat' ? `${g.data.public ? 'public' : 'private'} NAT in ${g.data.subnet}${g.data.publicIps.length ? ` · ${g.data.publicIps.join(', ')}` : ''}` : null })),
      endpoints: list('endpoint').map((e) => ({ id: e.id, service: e.data.service, kind: e.data.kind, policyOpen: e.data.policyOpen })),
      firewalls: list('firewall').map((f) => ({ id: f.id, name: f.name, subnets: f.data.subnets, policy: f.data.policy })),
      loadBalancers: list('lb').map((b) => ({ id: b.id, account: b.owner, name: b.name, scheme: b.data.scheme, kind: b.data.kind, listeners: b.data.listeners, groups: b.data.groups })),
      interfaces: enis.map((e) => ({ id: e.id, account: e.owner, name: e.name, subnet: e.data.subnet, privateIp: e.data.privateIp, publicIp: e.data.publicIp, groups: e.data.groups, kind: e.data.kind, instance: e.data.instance })),
      flowLogs: m.items.some((i) => i.cloud === 'aws' && i.owner === n.owner && i.type === 'flow-log' && i.data.resource === n.nativeId && i.data.status === 'ACTIVE'),
      flowLogList: flowLogsOf(m, (i) => i.owner === n.owner && (i.data.resource === n.nativeId || subnets.some((s) => s.id === i.data.resource))),
      clientVpns: list('client-vpn').map((c) => ({ id: c.id, name: c.name, ...c.data })),
      resolver: { endpoints: list('resolver-endpoint').map((e) => ({ id: e.id, name: e.name, ...e.data })),
        rules: m.items.filter((i) => i.cloud === 'aws' && i.owner === n.owner && i.type === 'resolver-rule' && i.data.vpcs.includes(n.nativeId)).map((r) => ({ id: r.id, name: r.name, ...r.data })) },
      endpointServices: m.items.filter((i) => i.cloud === 'aws' && i.owner === n.owner && i.type === 'endpoint-service' && list('lb').some((b) => i.data.nlbs.includes(b.id) || i.data.glbs.includes(b.id)))
        .map((v) => ({ id: v.id, name: v.name, acceptance: v.data.acceptance, connections: v.data.connections })) };
  }
  if (n.kind === 'network' && (!n.stub || only)) {
    const nets = m.items.filter((i) => i.cloud === 'gcp' && i.type === 'network' && i.id === n.nativeId);
    const fw = m.items.filter((i) => i.cloud === 'gcp' && i.type === 'firewall' && i.vpc === n.nativeId);
    const insts = m.items.filter((i) => i.cloud === 'gcp' && i.type === 'instance' && i.data.interfaces.some((x) => x.network === n.nativeId) && (!only || i.owner === only));
    return { ...base, peerings: nets[0]?.data.peerings || [], routingMode: nets[0]?.data.routingMode || null, auto: !!nets[0]?.data.autoSubnets,
      subnets: m.items.filter((i) => i.cloud === 'gcp' && i.type === 'subnet' && i.vpc === n.nativeId).map((s) => ({ id: s.id, name: s.name, region: s.region, cidr: s.data.cidr, privateGoogleAccess: s.data.privateGoogleAccess, flowLogs: s.data.flowLogs, purpose: s.data.purpose })),
      firewallRules: fw.map((f) => ({ id: f.id, name: f.name, ...f.data })).sort((a, b) => a.priority - b.priority),
      firewallPolicies: m.items.filter((i) => i.cloud === 'gcp' && i.type === 'firewall-policy' && i.data.networks.includes(n.nativeId)).map((p) => ({ id: p.id, name: p.name, rules: p.data.rules })),
      routers: m.items.filter((i) => i.cloud === 'gcp' && i.type === 'router' && i.vpc === n.nativeId).map((r) => ({ id: r.id, name: r.name, region: r.region, asn: r.data.asn, peers: r.data.peers, nats: r.data.nats })),
      routes: m.items.filter((i) => i.cloud === 'gcp' && i.type === 'route' && i.vpc === n.nativeId).map((r) => ({ id: r.id, name: r.name, ...r.data })),
      instances: insts.map((i) => ({ id: i.id, name: i.name, zone: i.region, owner: i.owner, tags: i.data.tags, serviceAccounts: i.data.serviceAccounts, interfaces: i.data.interfaces.filter((x) => x.network === n.nativeId) })) };
  }
  if (n.kind === 'tgw') {
    const atts = m.items.filter((i) => i.cloud === 'aws' && i.type === 'tgw-attachment' && i.data.tgw === n.nativeId);
    const seen = new Set();
    return { ...base, attachments: atts.filter((a) => !seen.has(a.id) && seen.add(a.id)).map((a) => ({ id: a.id, name: a.name, resourceType: a.data.resourceType, resourceId: a.data.resourceId, resourceOwner: a.data.resourceOwner, state: a.data.state })),
      routeTables: m.items.filter((i) => i.cloud === 'aws' && i.type === 'tgw-route-table' && i.data.tgw === n.nativeId).map((t) => ({ id: t.id, name: t.name, default: t.data.default, associations: t.data.associations, routes: t.data.routes })) };
  }
  if (n.kind === 'dxgw') {
    const vifs = m.items.filter((i) => i.cloud === 'aws' && i.type === 'dx-vif' && i.data.dxgw === n.nativeId);
    const conns = m.items.filter((i) => i.cloud === 'aws' && i.type === 'dx-connection' && vifs.some((v) => v.data.connection === i.id));
    return { ...base, vifs: vifs.map((v) => ({ id: v.id, name: v.name, ...v.data })), connections: conns.map((c) => ({ id: c.id, name: c.name, ...c.data })),
      associations: m.items.filter((i) => i.cloud === 'aws' && i.type === 'dx-association' && i.data.dxgw === n.nativeId).map((a) => ({ id: a.id, ...a.data })) };
  }
  if (n.kind === 'hub') return { ...base, spokes: m.items.filter((i) => i.cloud === 'gcp' && i.type === 'ncc-spoke' && i.data.hub === n.nativeId).map((x) => ({ id: x.id, name: x.name, ...x.data, network: x.vpc })) };
  return base;
}

/** Everything read, as rows: one type (or all), filtered by a search. */
export async function networkInventory(user, q = {}) {
  const m = await model(), v = visible(user, m);
  const text = String(q.q || '').toLowerCase();
  const rows = m.items.filter((i) => v.ok(i.cloud, i.owner) && (!q.type || i.type === q.type) && (!q.cloud || i.cloud === q.cloud)
    && (!text || `${i.name} ${i.id} ${i.owner} ${i.vpc || ''} ${JSON.stringify(i.data)}`.toLowerCase().includes(text)));
  const types = {}; for (const i of m.items.filter((x) => v.ok(x.cloud, x.owner))) types[i.type] = (types[i.type] || 0) + 1;
  return { total: rows.length, types, items: rows.slice(0, 500).map((i) => ({ cloud: i.cloud, owner: i.owner, region: i.region, type: i.type, id: i.id, name: i.name, vpc: i.vpc, data: i.data })) };
}

export async function decideNetFinding(user, id, { decision, note }) {
  if (!['expected', 'investigate'].includes(decision)) throw new NetError(400, 'Pick expected or investigate.');
  if (decision === 'expected' && !String(note || '').trim()) throw new NetError(400, 'Say why it is expected.');
  await mayDecide(user, id);
  const r = (await query(`UPDATE net_findings SET decision = $2, note = $3, decided_by = $4, decided_at = now() WHERE id = $1 AND status = 'open' RETURNING *`, [id, decision, String(note || '').slice(0, 1000) || null, user.id])).rows[0];
  if (!r) throw new NetError(404, 'Not found, or already resolved.');
  return r;
}
async function mayDecide(user, id) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id))) throw new NetError(404, 'Not found.');
  const f = (await query('SELECT cloud, owner FROM net_findings WHERE id = $1', [id])).rows[0];
  if (!f || !visible(user, await model()).ok(f.cloud, f.owner)) throw new NetError(404, 'Not found.');
}
export async function undecideNetFinding(user, id) {
  await mayDecide(user, id);
  const r = (await query(`UPDATE net_findings SET decision = NULL, note = NULL, decided_by = NULL, decided_at = NULL WHERE id = $1 RETURNING *`, [id])).rows[0];
  if (!r) throw new NetError(404, 'Not found.');
  return r;
}
