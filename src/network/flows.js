// VPC flow logs, from the S3 buckets they are delivered to. Each record is attributed to the line of the map it
// travelled on, the way AWS routes it: the interface's subnet → its route table → the longest matching route (prefix
// lists included) → the target (local, an internet or NAT gateway, a peering connection, a transit gateway, a virtual
// private gateway, a gateway endpoint). Past a transit gateway or a virtual private gateway, the destination address
// says where it went (another VPC, a Google Cloud network across a VPN, on-premises), and every line on the way counts.
// What reaches a public address from the internet is kept per port. Files are read once each, newest window first
// to the lookback, a budget at a time; hours are kept 30 days.
import zlib from 'node:zlib';
import { query, tx, pool } from '../db.js';
import { getGateway } from '../aws/gateway.js';
import { range4, shareAware } from './analyze.js';
import { isEnabled } from '../extensions.js';

export const LOOKBACK_DAYS = Number(process.env.FLOW_LOOKBACK_DAYS || 7);
const BUDGET_BYTES = Number(process.env.FLOW_BUDGET_MB || 48) * 1048576, BUDGET_FILES = Number(process.env.FLOW_BUDGET_FILES || 300);
const LOCK = 731_000_002;
const PROTO = { 6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6' };
const HOUR = 36e5;

// ---------------------------------------------------------------- files
/** The bucket and key prefix of a flow log's S3 destination ARN (arn:aws:s3:::bucket/optional/prefix). */
export function s3Dest(arn) {
  const m = String(arn || '').match(/^arn:aws[a-z-]*:s3:::([^/]+)\/?(.*)$/);
  return m ? { bucket: m[1], prefix: m[2].replace(/\/+$/, '') } : null;
}
/** The key prefix of one day's files: <prefix>/AWSLogs/<account>/vpcflowlogs/<region>/YYYY/MM/DD/ (Hive-style if asked). */
export function dayPrefix({ prefix, account, region, hive }, day) {
  const d = new Date(day), y = d.getUTCFullYear(), mo = String(d.getUTCMonth() + 1).padStart(2, '0'), da = String(d.getUTCDate()).padStart(2, '0');
  const k = hive ? `AWSLogs/aws-account-id=${account}/aws-service=vpcflowlogs/aws-region=${region}/year=${y}/month=${mo}/day=${da}/` : `AWSLogs/${account}/vpcflowlogs/${region}/${y}/${mo}/${da}/`;
  return `${prefix ? `${prefix}/` : ''}${k}`;
}
/** When a file's window ended, from its name: <account>_vpcflowlogs_<region>_<fl-id>_<YYYYMMDDTHHmmZ>_<hash>.log.gz */
export function fileTime(key) {
  const m = String(key).match(/_(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})Z_[^/]*$/);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) : null;
}
/** Records of one file, by its header line (default and custom formats alike). */
export function* parseFlowText(text) {
  let cols = null;
  for (const line of text.split('\n')) {
    if (!line) continue;
    const parts = line.split(' ');
    if (!cols) { cols = parts; if (!cols.includes('interface-id')) { cols = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status'.split(' '); } else continue; }
    const r = {}; for (let i = 0; i < cols.length; i++) r[cols[i]] = parts[i];
    if (r['log-status'] && r['log-status'] !== 'OK') continue;
    yield r;
  }
}

// ---------------------------------------------------------------- routing
const ip4 = (s) => { const p = String(s).split('.'); if (p.length !== 4) return null; let v = 0; for (const x of p) { const n = Number(x); if (!(n >= 0 && n <= 255) || x === '') return null; v = v * 256 + n; } return v; };
const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16'].map(range4);
const isPrivate = (v) => PRIVATE.some(([a, b]) => v >= a && v <= b);

/**
 * Where a record went: built once per read from the stored networking and the map (src/network/analyze.js graph).
 * route(record) → { side, dir, port, proto, links: [link ids], exposure: target|null } or null when it is not ours to count.
 */
export function flowRouter(rawItems, graph) {
  // a member's interface in a shared VPC travels the owner's subnets and route tables
  const items = shareAware(rawItems).items;
  const aws = items.filter((i) => i.cloud === 'aws');
  const k = (o, id) => `${o}|${id}`;
  const eniById = new Map(aws.filter((i) => i.type === 'eni').map((e) => [e.id, e]));
  const subnets = new Map(aws.filter((i) => i.type === 'subnet').map((s) => [k(s.owner, s.id), s]));
  const rts = aws.filter((i) => i.type === 'route-table');
  const rtOf = new Map(); for (const t of rts) for (const s of t.data.subnets) rtOf.set(k(t.owner, s), t);
  const mainRt = new Map(rts.filter((t) => t.data.main).map((t) => [k(t.owner, t.vpc), t]));
  const vpcCidr = new Map(aws.filter((i) => i.type === 'vpc').map((v) => [k(v.owner, v.id), v.data.cidrs]));
  const pls = new Map(aws.filter((i) => i.type === 'prefix-list').map((p) => [p.id, p.data.entries]));
  // a route table as ranges, most specific first; the VPC's own range is always local
  const tables = new Map();
  const ranges = (t, owner, vpc) => {
    const key = t ? k(t.owner, t.id) : `main|${owner}|${vpc}`;
    if (tables.has(key)) return tables.get(key);
    const out = (vpcCidr.get(k(owner, vpc)) || []).map((c) => ({ r: range4(c), target: { type: 'local' } }));
    for (const x of t?.data.routes || []) {
      if (x.state === 'blackhole') continue;
      const cidrs = /^pl-/.test(x.dest || '') ? pls.get(x.dest) || [] : [x.dest];
      for (const c of cidrs) { const r = range4(c); if (r) out.push({ r, target: x.target }); }
    }
    out.sort((a, b) => (a.r[1] - a.r[0]) - (b.r[1] - b.r[0]));
    tables.set(key, out); return out;
  };
  const lpm = (table, v) => table.find((x) => v >= x.r[0] && v <= x.r[1])?.target || null;

  // the map's lines, indexed the ways a record reaches them
  const dxAt = new Map(), internetOf = new Map(), peeringOf = new Map(), tgwLink = new Map(), atVpc = new Map(), plOf = new Map(), cvpnOf = new Map(), vpnById = new Map(), dxOfTgw = new Map();
  const adj = new Map(); const edge = (a, b, id) => { if (!adj.has(a)) adj.set(a, []); adj.get(a).push({ to: b, id }); };
  for (const l of graph.links) {
    if (l.kind === 'internet') { internetOf.set(l.from === 'internet' ? l.to : l.from, l.id); continue; }
    edge(l.from, l.to, l.id); edge(l.to, l.from, l.id);
    if (l.kind === 'peering' && l.nativeId) peeringOf.set(l.nativeId, l.id);
    if (l.kind === 'tgw') { const [v, t] = l.from.startsWith('aws:tgw:') ? [l.to, l.from] : [l.from, l.to]; tgwLink.set(`${v}|${t}`, l.id); }
    if (l.kind === 'vpn') for (const v of l.vpns || []) vpnById.set(v.id, l.id);
    if (l.kind === 'dx' && (l.from.startsWith('aws:tgw:') || l.to.startsWith('aws:tgw:'))) dxOfTgw.set(l.from.startsWith('aws:tgw:') ? l.from : l.to, l.id);
    if (l.kind === 'dx') for (const end of [l.from, l.to]) if (end.startsWith('aws:dxgw:')) { if (!dxAt.has(end)) dxAt.set(end, []); dxAt.get(end).push(l.id); }
    if (l.kind === 'privatelink' && l.endpoint) plOf.set(l.endpoint, l.id);
    if (l.kind === 'client-vpn') cvpnOf.set(l.from.startsWith('aws:vpc:') ? l.from : l.to, l.id);
    for (const end of [l.from, l.to]) if (end.startsWith('aws:vpc:') && ['vpn', 'dx'].includes(l.kind)) { if (!atVpc.has(end)) atVpc.set(end, []); atVpc.get(end).push(l.id); }
  }
  // which node owns an address: VPC and network ranges (most specific first), and your public addresses
  const owned = [];
  for (const n of graph.nodes) if (n.kind !== 'slice') for (const c of n.cidrs || []) { const r = range4(c); if (r) owned.push({ r, id: n.id }); }
  owned.sort((a, b) => (a.r[1] - a.r[0]) - (b.r[1] - b.r[0]));
  const ownerOf = (v) => owned.find((x) => v >= x.r[0] && v <= x.r[1])?.id || null;
  const mine = new Set([...aws.filter((i) => i.type === 'eni').flatMap((e) => [e.data.publicIp, ...(e.data.publicIps || [])]), ...aws.filter((i) => i.type === 'nat').flatMap((n) => n.data.publicIps),
    ...items.filter((i) => i.cloud === 'gcp' && i.type === 'instance').flatMap((i) => i.data.interfaces.flatMap((x) => x.natIps))].filter(Boolean));
  const tgwTables = new Map(); for (const t of aws.filter((i) => i.type === 'tgw-route-table')) { if (!tgwTables.has(t.data.tgw)) tgwTables.set(t.data.tgw, []); tgwTables.get(t.data.tgw).push(t); }
  const endpointEni = new Map(), lbOfEni = new Map();
  const lbs = aws.filter((i) => i.type === 'lb');
  for (const e of eniById.values()) {
    const vpce = String(e.data.description || '').match(/vpce-[0-9a-z]+/); if (vpce && e.data.kind === 'vpc_endpoint') for (const ip of [e.data.privateIp]) endpointEni.set(ip, vpce[0]);
    const elb = String(e.data.description || '').match(/^ELB ((?:app|net)\/[^/]+\/[0-9a-z]+)/); if (elb) { const lb = lbs.find((b) => b.id.endsWith(`/${elb[1]}`)); if (lb) lbOfEni.set(e.id, lb.id); }
  }
  // the lines between two nodes (fewest hops), not through the internet
  const paths = new Map();
  const path = (from, to) => {
    const key = `${from}>${to}`; if (paths.has(key)) return paths.get(key);
    const prev = new Map([[from, null]]), q = [from];
    while (q.length && !prev.has(to)) { const n = q.shift(); for (const e of adj.get(n) || []) if (!prev.has(e.to)) { prev.set(e.to, { n, id: e.id }); q.push(e.to); } }
    const out = []; if (prev.has(to)) for (let c = to; prev.get(c); c = prev.get(c).n) out.push(prev.get(c).id);
    if (out.length > 6) out.length = 0;
    paths.set(key, out); return out;
  };

  const cache = new Map();
  return function route(r) {
    const e = eniById.get(r['interface-id']); if (!e || e.data.kind === 'nat_gateway') return null;
    const vo = e.vpcOwner || e.owner, side = `aws:vpc:${vo}:${e.vpc}`;
    const mineIps = [e.data.privateIp, e.data.publicIp, ...(e.data.publicIps || [])];
    const localIsSrc = mineIps.includes(r.srcaddr) || (!mineIps.includes(r.dstaddr) && ownerOf(ip4(r.srcaddr)) === side);
    const remote = localIsSrc ? r.dstaddr : r.srcaddr, rv = ip4(remote); if (rv == null) return null;
    const lp = Number(localIsSrc ? r.srcport : r.dstport) || 0, rp = Number(localIsSrc ? r.dstport : r.srcport) || 0;
    const remoteServes = rp > 0 && (lp === 0 || rp < lp);
    const out = { side, dir: remoteServes ? 'out' : 'in', port: remoteServes ? rp : lp, proto: PROTO[r.protocol] || String(r.protocol), links: [], exposure: null };
    const ck = `${e.id}|${remote}`;
    let hit = cache.get(ck);
    if (!hit) {
      const s = subnets.get(k(vo, e.data.subnet)), t = s ? rtOf.get(k(s.owner, s.id)) || mainRt.get(k(s.owner, s.vpc)) : null;
      const target = lpm(ranges(t, vo, e.vpc), rv) || { type: 'none' };
      const links = [];
      const dest = isPrivate(rv) || !mine.has(remote) ? ownerOf(rv) : null;
      if (target.type === 'local') {
        if (endpointEni.has(remote) && plOf.has(endpointEni.get(remote))) links.push(plOf.get(endpointEni.get(remote)));
        if (/ClientVPN/i.test(e.data.description || '') && cvpnOf.has(side)) links.push(cvpnOf.get(side));
      } else if (['igw', 'eigw', 'nat'].includes(target.type)) { if (internetOf.has(side)) links.push(internetOf.get(side)); }
      else if (target.type === 'peering') { if (peeringOf.has(target.id)) links.push(peeringOf.get(target.id)); }
      else if (target.type === 'tgw') {
        const tgw = `aws:tgw:${target.id}`;
        if (tgwLink.has(`${side}|${tgw}`)) links.push(tgwLink.get(`${side}|${tgw}`));
        if (dest && dest !== side) links.push(...path(tgw, dest));
        else {
          // not one of ours: the transit gateway's own routes say which attachment (a VPN, Direct Connect)
          const tr = (tgwTables.get(target.id) || []).flatMap((x) => x.data.routes).filter((x) => x.state === 'active').map((x) => ({ r: range4(x.dest), a: x.attachments[0] })).filter((x) => x.r && x.a)
            .sort((a, b) => (a.r[1] - a.r[0]) - (b.r[1] - b.r[0])).find((x) => rv >= x.r[0] && rv <= x.r[1]);
          if (tr?.a.resourceType === 'vpn' && vpnById.has(tr.a.resourceId)) links.push(vpnById.get(tr.a.resourceId));
          else if (tr?.a.resourceType === 'direct-connect-gateway') links.push(...(dxAt.get(`aws:dxgw:${tr.a.resourceId}`) || (dxOfTgw.has(tgw) ? [dxOfTgw.get(tgw)] : [])));
          else if (tr?.a.resourceType === 'vpc') { const v = graph.nodes.find((n) => n.kind === 'vpc' && n.nativeId === tr.a.resourceId); if (v && tgwLink.has(`${v.id}|${tgw}`)) links.push(tgwLink.get(`${v.id}|${tgw}`)); }
        }
      } else if (target.type === 'vgw') {
        const here = atVpc.get(side) || [];
        const via = dest ? here.filter((id) => path(side, dest)[0] === id) : [];
        links.push(...(via.length ? via : here));
        if (dest && via.length) links.push(...path(side, dest).slice(1));
      }
      hit = { links: [...new Set(links)], viaIgw: target.type === 'igw' };
      cache.set(ck, hit);
    }
    out.links = hit.links;
    // the internet reaching a public address of ours
    if (hit.viaIgw && out.dir === 'in' && !isPrivate(rv) && !mine.has(remote)) out.exposure = lbOfEni.get(e.id) || e.id;
    out.remote = remote;
    return out;
  };
}

/** Totals of a batch of records: { links: Map(key -> row), exposure: Map(key -> row with sources Set) }. */
export function aggregate(records, route, into = { links: new Map(), exposure: new Map() }) {
  for (const r of records) {
    const x = route(r); if (!x) continue;
    const hour = new Date(Math.floor(Number(r.start) * 1000 / HOUR) * HOUR).toISOString();
    const bytes = Number(r.bytes) || 0, packets = Number(r.packets) || 0, action = r.action === 'REJECT' ? 'REJECT' : 'ACCEPT';
    for (const id of x.links) {
      const key = `${hour}|${id}|${x.side}|${x.dir}|${x.port}|${x.proto}|${action}`;
      const row = into.links.get(key) || into.links.set(key, { hour, link: id, side: x.side, dir: x.dir, port: x.port, proto: x.proto, action, bytes: 0, packets: 0, records: 0 }).get(key);
      row.bytes += bytes; row.packets += packets; row.records++;
    }
    if (x.exposure) {
      const key = `${hour}|${x.exposure}|${x.port}|${x.proto}|${action}`;
      const row = into.exposure.get(key) || into.exposure.set(key, { hour, target: x.exposure, port: x.port, proto: x.proto, action, bytes: 0, records: 0, sources: new Set() }).get(key);
      row.bytes += bytes; row.records++; if (row.sources.size < 5000) row.sources.add(x.remote);
    }
  }
  return into;
}

async function saveBatch(agg, files) {
  const L = [...agg.links.values()], E = [...agg.exposure.values()];
  await tx(async (c) => {
    for (let i = 0; i < L.length; i += 1000) {
      const p = L.slice(i, i + 1000);
      await c.query(`INSERT INTO net_flow_hourly(hour, link_id, side, dir, port, proto, action, bytes, packets, records)
        SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::text[], $4::text[], $5::int[], $6::text[], $7::text[], $8::bigint[], $9::bigint[], $10::bigint[])
        ON CONFLICT (hour, link_id, side, dir, port, proto, action) DO UPDATE SET bytes = net_flow_hourly.bytes + EXCLUDED.bytes, packets = net_flow_hourly.packets + EXCLUDED.packets, records = net_flow_hourly.records + EXCLUDED.records`,
      [p.map((x) => x.hour), p.map((x) => x.link), p.map((x) => x.side), p.map((x) => x.dir), p.map((x) => x.port), p.map((x) => x.proto), p.map((x) => x.action), p.map((x) => x.bytes), p.map((x) => x.packets), p.map((x) => x.records)]);
    }
    for (let i = 0; i < E.length; i += 1000) {
      const p = E.slice(i, i + 1000);
      await c.query(`INSERT INTO net_flow_exposure(hour, target, port, proto, action, records, bytes, sources)
        SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::int[], $4::text[], $5::text[], $6::bigint[], $7::bigint[], $8::int[])
        ON CONFLICT (hour, target, port, proto, action) DO UPDATE SET records = net_flow_exposure.records + EXCLUDED.records, bytes = net_flow_exposure.bytes + EXCLUDED.bytes, sources = GREATEST(net_flow_exposure.sources, EXCLUDED.sources)`,
      [p.map((x) => x.hour), p.map((x) => x.target), p.map((x) => x.port), p.map((x) => x.proto), p.map((x) => x.action), p.map((x) => x.records), p.map((x) => x.bytes), p.map((x) => x.sources.size)]);
    }
    for (const f of files) await c.query(`INSERT INTO net_flow_files(bucket, key, flow_log, owner, vpc_node, file_time, size, records) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
      [f.bucket, f.key, f.flowLog, f.owner, f.vpcNode, new Date(f.time), f.size, f.records]);
  });
}

const DENIED = /AccessDenied|not authorized|Forbidden|403|KMS/i;
async function noteRead(fl, patch) {
  await query(`INSERT INTO net_flow_reads(flow_log, owner, vpc_node, bucket, prefix, last_time, files, bytes, note, error, read_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
    ON CONFLICT (flow_log) DO UPDATE SET owner = EXCLUDED.owner, vpc_node = EXCLUDED.vpc_node, bucket = EXCLUDED.bucket, prefix = EXCLUDED.prefix,
      last_time = GREATEST(net_flow_reads.last_time, EXCLUDED.last_time), files = net_flow_reads.files + EXCLUDED.files, bytes = net_flow_reads.bytes + EXCLUDED.bytes, note = EXCLUDED.note, error = EXCLUDED.error, read_at = now()`,
  [fl.id, fl.owner, fl.vpc ? `aws:vpc:${fl.vpcOwner || fl.owner}:${fl.vpc}` : null, patch.bucket || null, patch.prefix ?? null, patch.lastTime ? new Date(patch.lastTime) : null, patch.files || 0, patch.bytes || 0, patch.note || null, patch.error || null]);
}

/**
 * Worker step: read new flow log files, a budget at a time. `gwFor(account row)` gives the gateway that reads a
 * bucket: the account that owns it when it is connected (a log archive account), else the flow log's own account.
 */
export async function flowTick({ log = () => {}, gwFor = null, now = Date.now(), analyze } = {}) {
  if (!(await isEnabled('networking'))) return null;
  const client = await pool.connect();
  try {
    if (!(await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK])).rows[0].ok) return null;
    try {
      const { loadItems, networkEstate } = await import('./sync.js');
      const { analyzeNetwork } = await import('./analyze.js');
      const items = await loadItems();
      const fls = shareAware(items).items.filter((i) => i.cloud === 'aws' && i.type === 'flow-log' && i.data.status === 'ACTIVE');
      if (!fls.length) return null;
      const graph = (analyze || analyzeNetwork)(items, await networkEstate()).graph;
      const route = flowRouter(items, graph);
      const accounts = (await query('SELECT * FROM cloud_accounts')).rows, byAcct = new Map(accounts.map((a) => [a.account_id, a]));
      const bucketOwner = new Map((await query(`SELECT r.name, a.account_id FROM resources r JOIN cloud_accounts a ON a.id = r.account_id WHERE r.service = 's3' AND r.deleted_at IS NULL`).catch(() => ({ rows: [] }))).rows.map((r) => [r.name, r.account_id]));
      const workspace = (await query('SELECT * FROM workspace')).rows[0];
      gwFor ||= (a) => getGateway(a, workspace);
      let bytes = 0, nfiles = 0;
      const out = { files: 0, records: 0, errors: 0 };
      for (const fl of fls) {
        if (fl.data.destination !== 's3') { await noteRead(fl, { note: `delivered to ${fl.data.destination === 'cloud-watch-logs' ? 'CloudWatch Logs' : fl.data.destination || 'somewhere else'}; only S3 is read` }); continue; }
        if (fl.data.fileFormat === 'parquet') { await noteRead(fl, { note: 'Parquet files are not read yet; plain text only' }); continue; }
        const dest = s3Dest(fl.data.arn); if (!dest) { await noteRead(fl, { note: 'no S3 destination' }); continue; }
        if (bytes >= BUDGET_BYTES || nfiles >= BUDGET_FILES) break;
        const reader = byAcct.get(bucketOwner.get(dest.bucket)) || byAcct.get(fl.owner);
        if (!reader) continue;
        let gw; try { gw = await gwFor(reader); } catch (e) { await noteRead(fl, { ...dest, error: String(e.message).slice(0, 300) }); out.errors++; continue; }
        if (!gw.listFlowLogObjects) continue;
        const since = Math.max(now - LOOKBACK_DAYS * 864e5, 0);
        const days = []; for (let d = Math.floor(now / 864e5) * 864e5; d >= Math.floor(since / 864e5) * 864e5; d -= 864e5) days.push(d);
        try {
          const keys = [];
          for (const d of days) for (const o of await gw.listFlowLogObjects({ bucket: dest.bucket, prefix: dayPrefix({ ...dest, account: fl.owner, region: fl.region, hive: fl.data.hive }, d) })) {
            const t = fileTime(o.key); if (t == null || t < since || !o.key.includes(`_${fl.id}_`)) continue;
            keys.push({ ...o, time: t });
          }
          const done = new Set((await query('SELECT key FROM net_flow_files WHERE bucket = $1 AND key = ANY($2)', [dest.bucket, keys.map((x) => x.key)])).rows.map((r) => r.key));
          const todo = keys.filter((x) => !done.has(x.key)).sort((a, b) => b.time - a.time);   // newest first, so the map is useful at once
          const agg = { links: new Map(), exposure: new Map() }, files = [];
          let fb = 0, last = null;
          for (const o of todo) {
            if (bytes >= BUDGET_BYTES || nfiles >= BUDGET_FILES) break;
            const buf = await gw.getFlowLogObject({ bucket: dest.bucket, key: o.key });
            const text = zlib.gunzipSync(buf).toString('utf8');
            let n = 0; const recs = [];
            for (const r of parseFlowText(text)) { recs.push(r); n++; }
            aggregate(recs, route, agg);
            files.push({ bucket: dest.bucket, key: o.key, flowLog: fl.id, owner: fl.owner, vpcNode: fl.vpc ? `aws:vpc:${fl.vpcOwner || fl.owner}:${fl.vpc}` : null, time: o.time, size: buf.length, records: n });
            bytes += buf.length; fb += buf.length; nfiles++; out.files++; out.records += n; last = Math.max(last || 0, o.time);
          }
          if (files.length) await saveBatch(agg, files);
          await noteRead(fl, { ...dest, lastTime: last, files: files.length, bytes: fb, note: todo.length > files.length ? `${todo.length - files.length} files still to read` : null });
        } catch (e) {
          out.errors++;
          await noteRead(fl, { ...dest, error: DENIED.test(`${e.name} ${e.message}`) ? `not allowed to read s3://${dest.bucket}/${dest.prefix ? `${dest.prefix}/` : ''}AWSLogs/…/vpcflowlogs/ as ${reader.name}: ${String(e.message).slice(0, 200)}` : String(e.message).slice(0, 300) });
          log('warn', 'flow logs not read', { flowLog: fl.id, error: e.message });
        }
      }
      await query(`DELETE FROM net_flow_files WHERE file_time < now() - interval '35 days'`);
      await query(`DELETE FROM net_flow_hourly WHERE hour < now() - interval '30 days'`);
      await query(`DELETE FROM net_flow_exposure WHERE hour < now() - interval '30 days'`);
      if (out.files) log('info', 'flow logs read', out);
      return out.files || out.errors ? out : null;
    } finally { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]); }
  } finally { client.release(); }
}

/**
 * What the flow logs say, for the analyzer and the page: per line, accepted and rejected traffic over `days` (and
 * the last 24 hours by the hour from `hourStart`); per VPC, how far back its flow logs were read; per public target and
 * port, what the internet reached.
 */
export async function loadUsage({ days = LOOKBACK_DAYS, hourStart = null } = {}) {
  const [links, cover, exp, hourly] = await Promise.all([
    query(`SELECT link_id, sum(bytes) FILTER (WHERE action = 'ACCEPT')::bigint AS bytes, sum(records) FILTER (WHERE action = 'ACCEPT')::bigint AS flows,
             sum(records) FILTER (WHERE action = 'REJECT')::bigint AS rejected, max(hour) FILTER (WHERE action = 'ACCEPT') AS last
             FROM net_flow_hourly WHERE hour >= now() - make_interval(days => $1) GROUP BY 1`, [days]),
    query(`SELECT vpc_node, min(file_time) AS since, max(file_time) AS until, count(*)::int AS files FROM net_flow_files WHERE file_time >= now() - make_interval(days => $1) GROUP BY 1`, [days]),
    query(`SELECT target, port, proto, sum(records) FILTER (WHERE action = 'ACCEPT')::bigint AS accepted, sum(records) FILTER (WHERE action = 'REJECT')::bigint AS rejected, max(sources)::int AS sources
             FROM net_flow_exposure WHERE hour >= now() - make_interval(days => $1) GROUP BY 1, 2, 3`, [days]),
    hourStart != null ? query(`SELECT link_id, hour, sum(bytes) FILTER (WHERE action = 'ACCEPT')::bigint AS bytes, sum(records) FILTER (WHERE action = 'REJECT')::bigint AS rejected
             FROM net_flow_hourly WHERE hour >= to_timestamp($1) AND hour < to_timestamp($2) GROUP BY 1, 2`, [hourStart / 1000, (hourStart + 864e5) / 1000]) : { rows: [] },
  ]);
  const ports = await query(`SELECT link_id, port, proto, sum(bytes)::bigint AS bytes FROM net_flow_hourly WHERE action = 'ACCEPT' AND hour >= now() - make_interval(days => $1) GROUP BY 1, 2, 3`, [days]);
  const L = new Map(links.rows.map((r) => [r.link_id, { bytes: Number(r.bytes || 0), flows: Number(r.flows || 0), rejected: Number(r.rejected || 0), last: r.last, ports: [], hourly: null }]));
  for (const r of ports.rows) L.get(r.link_id)?.ports.push({ port: r.port, proto: r.proto, bytes: Number(r.bytes) });
  for (const x of L.values()) { x.ports.sort((a, b) => b.bytes - a.bytes); x.ports = x.ports.slice(0, 8); }
  for (const r of hourly.rows) {
    const x = L.get(r.link_id) || L.set(r.link_id, { bytes: 0, flows: 0, rejected: 0, last: null, ports: [] }).get(r.link_id);
    x.hourly ||= Array.from({ length: 24 }, () => ({ bytes: 0, rejected: 0 }));
    const b = Math.max(0, Math.min(23, Math.floor((new Date(r.hour).getTime() - hourStart) / HOUR)));
    x.hourly[b].bytes += Number(r.bytes || 0); x.hourly[b].rejected += Number(r.rejected || 0);
  }
  const C = new Map(cover.rows.map((r) => [r.vpc_node, { since: r.since, until: r.until, files: r.files }]));
  const E = new Map();
  for (const r of exp.rows) { if (!E.has(r.target)) E.set(r.target, new Map()); E.get(r.target).set(`${r.proto}|${r.port}`, { accepted: Number(r.accepted || 0), rejected: Number(r.rejected || 0), sources: r.sources || 0 }); }
  return { links: L, coverage: C, exposure: E, days };
}
