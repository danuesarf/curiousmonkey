// VPC flow logs, from the S3 buckets they are delivered to. Each record is attributed to the line of the map it
// travelled on, the way AWS routes it: the interface's subnet → its route table → the longest matching route (prefix
// lists included) → the target (local, an internet or NAT gateway, a peering connection, a transit gateway, a virtual
// private gateway, a gateway endpoint). Past a transit gateway or a virtual private gateway, the destination address
// says where it went (another VPC, a Google Cloud network across a VPN, on-premises), and every line on the way counts.
// What reaches a public address from the internet is kept per port.
//
// Reading. Only a flow log's own files are listed (their names start <account>_vpcflowlogs_<region>_<fl-id>_), so
// flow logs sharing a bucket never list each other's. Each flow log keeps how far it is read (net_flow_reads): forward,
// listed again from two hours before where it got to, at most every 5 minutes (AWS delivers every 5); and back through
// the lookback, a day (or an hour) folder at a time, never listed again once read. Every flow log gets its new files
// before any gets history, and history goes in turns, so every VPC is current before any is deep. A few files at a
// time, each unzipped and counted as it streams. One flow log per VPC and kind of traffic is read, so nothing counts
// twice; one that keeps rejected traffic only, or a subnet's or an interface's, cannot say that a line is unused.
// Kept: hours and exposure for the lookback and a day; the names of the files read, two days past the lookback.
import zlib from 'node:zlib';
import { query, tx, pool } from '../db.js';
import { getGateway } from '../aws/gateway.js';
import { range4, shareAware, portsIn, ADMIN_PORTS, DATA_PORTS } from './analyze.js';
import { isEnabled } from '../extensions.js';

export const LOOKBACK_DAYS = Math.max(1, Number(process.env.FLOW_LOOKBACK_DAYS || 7));
export const KEEP_DAYS = LOOKBACK_DAYS + 1;              // hours and exposure: the lookback, and the 24 hours shown before it
const KEEP_FILES_DAYS = LOOKBACK_DAYS + 2;               // the files read, so none is read twice
const BUDGET_BYTES = Number(process.env.FLOW_BUDGET_MB || 48) * 1048576, BUDGET_FILES = Number(process.env.FLOW_BUDGET_FILES || 300);
const BUDGET_LISTS = 400;                                // folder listings in one step
const PARALLEL = Math.max(1, Number(process.env.FLOW_PARALLEL || 4));
const LOCK = 731_000_002;
const PROTO = { 6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6' };
const MINUTE = 6e4, HOUR = 36e5, DAY = 864e5;
const LATE = 2 * HOUR;                                   // a file can land after newer ones: each listing goes back this far
const LIST_EVERY = 5 * MINUTE;                           // AWS delivers flow log files every 5 minutes
const RETRY_EVERY = 15 * MINUTE;                         // a flow log that could not be read is tried again after this
const VOUCH = 48 * HOUR;                                 // listed and found nothing: still covered, this long past the newest file
const PORTS_KEPT = 40;                                   // per hour, line, side, direction and protocol in one read; the rest fold into port 0
// what a record needs to be put on a line
const NEED = ['interface-id', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol', 'bytes', 'start', 'action'];
const DEFAULT_COLS = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status'.split(' ');
const NOTABLE = new Set([...Object.keys(ADMIN_PORTS), ...Object.keys(DATA_PORTS)].map(Number));
/** How the reader runs, as Operations says it. */
export const FLOW_SETTINGS = { lookbackDays: LOOKBACK_DAYS, keepDays: KEEP_DAYS, stepFiles: BUDGET_FILES, stepMb: BUDGET_BYTES / 1048576, parallel: PARALLEL, listEveryMin: LIST_EVERY / MINUTE, everySeconds: 60 };

// ---------------------------------------------------------------- files
/** The bucket and key prefix of a flow log's S3 destination ARN (arn:aws:s3:::bucket/optional/prefix). */
export function s3Dest(arn) {
  const m = String(arn || '').match(/^arn:aws[a-z-]*:s3:::([^/]+)\/?(.*)$/);
  return m ? { bucket: m[1], prefix: m[2].replace(/\/+$/, '') } : null;
}
const pad = (n) => String(n).padStart(2, '0');
/** The key prefix of one day's files: <prefix>/AWSLogs/<account>/vpcflowlogs/<region>/YYYY/MM/DD/ (Hive-style if asked). */
export function dayPrefix({ prefix, account, region, hive }, day) {
  const d = new Date(day), y = d.getUTCFullYear(), mo = pad(d.getUTCMonth() + 1), da = pad(d.getUTCDate());
  const k = hive ? `AWSLogs/aws-account-id=${account}/aws-service=vpcflowlogs/aws-region=${region}/year=${y}/month=${mo}/day=${da}/` : `AWSLogs/${account}/vpcflowlogs/${region}/${y}/${mo}/${da}/`;
  return `${prefix ? `${prefix}/` : ''}${k}`;
}
/** The folder a file of time `t` lands in: its day's, or its hour's with per-hour partitions. → { prefix, start, end } */
export function folderOf(dest, t) {
  if (!dest.perHour) { const start = Math.floor(t / DAY) * DAY; return { prefix: dayPrefix(dest, start), start, end: start + DAY }; }
  const start = Math.floor(t / HOUR) * HOUR, hh = pad(new Date(start).getUTCHours());
  return { prefix: `${dayPrefix(dest, start)}${dest.hive ? `hour=${hh}` : hh}/`, start, end: start + HOUR };
}
/** How a flow log's file names start: <account>_vpcflowlogs_<region>_<fl-id>_ (the time follows, so names sort by it). */
export const fileStem = ({ account, region }, id) => `${account}_vpcflowlogs_${region}_${id}_`;
const stamp = (t) => { const d = new Date(t); return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}`; };
/** When a file's window ended, from its name: <account>_vpcflowlogs_<region>_<fl-id>_<YYYYMMDDTHHmmZ>_<hash>.log.gz */
export function fileTime(key) {
  const m = String(key).match(/_(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})Z_[^/]*$/);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) : null;
}
const fieldsOf = (format) => [...String(format).matchAll(/\$\{([a-z0-9-]+)\}/g)].map((m) => m[1]);
/** Records of one file, by its header line (default and custom formats alike). */
export function* parseFlowText(text) {
  let cols = null;
  for (const line of text.split('\n')) {
    if (!line) continue;
    const parts = line.split(' ');
    if (!cols) { cols = parts; if (!cols.includes('interface-id')) { cols = DEFAULT_COLS; } else continue; }
    const r = {}; for (let i = 0; i < cols.length; i++) r[cols[i]] = parts[i];
    if (r['log-status'] && r['log-status'] !== 'OK') continue;
    yield r;
  }
}
/** Where each needed column is, from a file's first line: its header (field names only), or a record in the default format. */
function columnsOf(first) {
  const parts = first.split(' '), header = parts.every((x) => /^[a-z][a-z0-9-]*$/.test(x)), cols = header ? parts : DEFAULT_COLS, at = (c) => cols.indexOf(c);
  return { header, missing: NEED.filter((c) => !cols.includes(c)),
    at: { eni: at('interface-id'), src: at('srcaddr'), dst: at('dstaddr'), sp: at('srcport'), dp: at('dstport'), proto: at('protocol'), bytes: at('bytes'), packets: at('packets'), start: at('start'), action: at('action'), status: at('log-status') } };
}
/**
 * Count one gzipped flow log file into `into` ({ links, exposure }), a chunk at a time: a 75 MB file never sits in
 * memory whole, and the worker answers between chunks. → { records, missing: [columns the file leaves out] }
 */
export async function countFlowFile(buf, route, into, opts = {}) {
  const gz = zlib.createGunzip({ chunkSize: 256 * 1024 });
  gz.end(buf);
  let rest = '', cols = null, records = 0;
  const r = {};   // one record at a time, refilled
  const line = (s) => {
    if (!s) return;
    if (!cols) { cols = columnsOf(s); if (cols.header) return; }
    if (cols.missing.length) return;
    const p = s.split(' '), a = cols.at;
    if (a.status >= 0 && p[a.status] !== 'OK') return;
    r['interface-id'] = p[a.eni]; r.srcaddr = p[a.src]; r.dstaddr = p[a.dst]; r.srcport = p[a.sp]; r.dstport = p[a.dp]; r.protocol = p[a.proto];
    r.bytes = p[a.bytes]; r.packets = a.packets >= 0 ? p[a.packets] : 0; r.start = p[a.start]; r.action = p[a.action];
    records++;
    addRecord(r, route, into, opts);
  };
  for await (const chunk of gz) {
    const s = rest + chunk.toString('latin1');   // flow logs are ASCII
    let i = 0, j;
    while ((j = s.indexOf('\n', i)) !== -1) { line(s.slice(i, j)); i = j + 1; }
    rest = s.slice(i);
  }
  line(rest);
  return { records, missing: cols?.missing || [] };
}

// ---------------------------------------------------------------- routing
const ip4 = (s) => { const p = String(s).split('.'); if (p.length !== 4) return null; let v = 0; for (const x of p) { const n = Number(x); if (!(n >= 0 && n <= 255) || x === '') return null; v = v * 256 + n; } return v; };
const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16'].map(range4);
const isPrivate = (v) => PRIVATE.some(([a, b]) => v >= a && v <= b);

/**
 * Where a record went: built once per read from the stored networking and the map (src/network/analyze.js graph).
 * route(record, vpc) → { side, dir, port, proto, links: [link ids], exposure: target|null, inbound, remoteLogged } or
 * null when it is not ours to count. `vpc`: the VPC node of the flow log the record came from, to place a record of
 * an interface the last networking read did not see (an ECS task, an instance started since) by its address.
 * `logged`: Map(VPC node -> since when, ms) of the VPCs whose flow logs are read in full; traffic between two of them is
 * in both, and is counted once, where it leaves.
 */
export function flowRouter(rawItems, graph, { logged = new Map() } = {}) {
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
  const vpcRanges = new Map([...vpcCidr].map(([key, cidrs]) => [key, (cidrs || []).map(range4).filter(Boolean)]));
  // each VPC's subnets by range, most specific first: where an interface not read yet sits
  const subnetsIn = new Map();
  for (const s of aws.filter((i) => i.type === 'subnet')) {
    const r = range4(s.data.cidr); if (!r) continue;
    const node = `aws:vpc:${s.vpcOwner || s.owner}:${s.vpc}`;
    (subnetsIn.get(node) || subnetsIn.set(node, []).get(node)).push({ r, s });
  }
  for (const list of subnetsIn.values()) list.sort((a, b) => (a.r[1] - a.r[0]) - (b.r[1] - b.r[0]));
  const unknownEni = (r, vpc) => {
    for (const addr of [r.srcaddr, r.dstaddr]) {
      const v = ip4(addr), hit = v == null ? null : subnetsIn.get(vpc)?.find((x) => v >= x.r[0] && v <= x.r[1]);
      if (hit) return { id: `?${hit.s.id}`, unknown: true, owner: hit.s.owner, vpcOwner: hit.s.vpcOwner, vpc: hit.s.vpc, data: { subnet: hit.s.id, privateIp: addr, publicIps: [], kind: 'interface', description: '' } };
    }
    return null;
  };
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
  // the VPC an address is in, only when no other node has the same range (two default VPCs are both 172.31.0.0/16)
  const onlyOwner = (v) => {
    const all = owned.filter((x) => v >= x.r[0] && v <= x.r[1]); if (!all.length) return null;
    const best = all.filter((x) => x.r[1] - x.r[0] === all[0].r[1] - all[0].r[0]);
    return new Set(best.map((x) => x.id)).size === 1 ? best[0].id : null;
  };
  const linkById = new Map(graph.links.map((l) => [l.id, l]));
  const mine = new Set([...aws.filter((i) => i.type === 'eni').flatMap((e) => [e.data.publicIp, ...(e.data.publicIps || [])]), ...aws.filter((i) => i.type === 'nat').flatMap((n) => n.data.publicIps),
    ...items.filter((i) => i.cloud === 'gcp' && i.type === 'instance').flatMap((i) => i.data.interfaces.flatMap((x) => x.natIps))].filter(Boolean));
  const tgwTables = new Map(); for (const t of aws.filter((i) => i.type === 'tgw-route-table')) { if (!tgwTables.has(t.data.tgw)) tgwTables.set(t.data.tgw, []); tgwTables.get(t.data.tgw).push(t); }
  const attachmentOf = new Map(aws.filter((i) => i.type === 'tgw-attachment' && i.data.resourceType === 'vpc').map((a) => [`${a.data.tgw}|${a.data.resourceId}`, a.id]));
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
  return function route(r, vpc) {
    const e = eniById.get(r['interface-id']) || (vpc ? unknownEni(r, vpc) : null); if (!e || e.data.kind === 'nat_gateway') return null;
    const vo = e.vpcOwner || e.owner, side = `aws:vpc:${vo}:${e.vpc}`, own = vpcRanges.get(k(vo, e.vpc)) || [];
    const inOwn = (v) => v != null && own.some(([a, b]) => v >= a && v <= b);
    // a transit gateway's interface in this VPC: what comes from or goes to this VPC is on that end's own interface too
    if (e.data.kind === 'transit_gateway' && (inOwn(ip4(r.srcaddr)) || inOwn(ip4(r.dstaddr)))) return null;
    const mineIps = [e.data.privateIp, e.data.publicIp, ...(e.data.publicIps || [])];
    // a secondary address (a pod's, on its node's interface) is this VPC's, not some other VPC's with the same range
    const localIsSrc = mineIps.includes(r.srcaddr) || (!mineIps.includes(r.dstaddr) && inOwn(ip4(r.srcaddr)));
    const remote = localIsSrc ? r.dstaddr : r.srcaddr, rv = ip4(remote); if (rv == null) return null;
    const lp = Number(localIsSrc ? r.srcport : r.dstport) || 0, rp = Number(localIsSrc ? r.dstport : r.srcport) || 0;
    const remoteServes = rp > 0 && (lp === 0 || rp < lp);
    const out = { side, dir: remoteServes ? 'out' : 'in', port: remoteServes ? rp : lp, proto: PROTO[r.protocol] || String(r.protocol), links: [], exposure: null, inbound: !localIsSrc, remoteSince: null };
    const ck = `${e.id}|${remote}`;
    let hit = cache.get(ck);
    if (!hit) {
      const s = subnets.get(k(vo, e.data.subnet)), t = s ? rtOf.get(k(s.owner, s.id)) || mainRt.get(k(s.owner, s.vpc)) : null;
      const target = lpm(ranges(t, vo, e.vpc), rv) || { type: 'none' };
      const links = [];
      const dest = isPrivate(rv) || !mine.has(remote) ? ownerOf(rv) : null;
      let rvpc = null;   // the VPC at the other end, when it is one of ours and certain
      if (target.type === 'local') {
        if (endpointEni.has(remote) && plOf.has(endpointEni.get(remote))) links.push(plOf.get(endpointEni.get(remote)));
        if (/ClientVPN/i.test(e.data.description || '') && cvpnOf.has(side)) links.push(cvpnOf.get(side));
      } else if (['igw', 'eigw', 'nat'].includes(target.type)) { if (internetOf.has(side)) links.push(internetOf.get(side)); }
      else if (target.type === 'peering') {
        if (peeringOf.has(target.id)) { const id = peeringOf.get(target.id), l = linkById.get(id); links.push(id); rvpc = l ? (l.from === side ? l.to : l.from) : null; }
      } else if (target.type === 'tgw') {
        const tgw = `aws:tgw:${target.id}`;
        if (tgwLink.has(`${side}|${tgw}`)) links.push(tgwLink.get(`${side}|${tgw}`));
        if (dest && dest !== side) { links.push(...path(tgw, dest)); rvpc = onlyOwner(rv); }
        else {
          // not one of ours: the transit gateway's routes say which attachment (a VPN, Direct Connect), in the route
          // table this VPC's attachment is associated with (one segment's default route is not another's)
          const att = attachmentOf.get(`${target.id}|${e.vpc}`), all = tgwTables.get(target.id) || [];
          const assoc = all.filter((x) => (x.data.associations || []).some((a) => (att && a.attachment === att) || (a.resourceType === 'vpc' && a.resourceId === e.vpc)));
          const tr = (assoc.length ? assoc : all).flatMap((x) => x.data.routes).filter((x) => x.state === 'active').map((x) => ({ r: range4(x.dest), a: x.attachments[0] })).filter((x) => x.r && x.a)
            .sort((a, b) => (a.r[1] - a.r[0]) - (b.r[1] - b.r[0])).find((x) => rv >= x.r[0] && rv <= x.r[1]);
          if (tr?.a.resourceType === 'vpn' && vpnById.has(tr.a.resourceId)) links.push(vpnById.get(tr.a.resourceId));
          else if (tr?.a.resourceType === 'direct-connect-gateway') links.push(...(dxAt.get(`aws:dxgw:${tr.a.resourceId}`) || (dxOfTgw.has(tgw) ? [dxOfTgw.get(tgw)] : [])));
          else if (tr?.a.resourceType === 'vpc') { const v = graph.nodes.find((n) => n.kind === 'vpc' && n.nativeId === tr.a.resourceId); if (v && tgwLink.has(`${v.id}|${tgw}`)) links.push(tgwLink.get(`${v.id}|${tgw}`)); }
        }
      } else if (target.type === 'vgw') {
        const here = atVpc.get(side) || [];
        const via = dest ? here.filter((id) => path(side, dest)[0] === id) : [];
        links.push(...(via.length ? via : here));
        if (dest && via.length) { links.push(...path(side, dest).slice(1)); rvpc = onlyOwner(rv); }
      }
      hit = { links: [...new Set(links)], viaIgw: target.type === 'igw', rvpc: rvpc?.startsWith('aws:vpc:') && rvpc !== side ? rvpc : null };
      if (cache.size >= 100_000) cache.clear();   // a busy public address meets millions of addresses; the work is cheap to redo
      cache.set(ck, hit);
    }
    out.links = hit.links;
    out.remoteSince = hit.rvpc && logged.has(hit.rvpc) ? logged.get(hit.rvpc) : null;
    // the internet reaching a public address of ours (not one of an interface not read yet: it is not on the map)
    if (!e.unknown && hit.viaIgw && out.dir === 'in' && !isPrivate(rv) && !mine.has(remote)) out.exposure = lbOfEni.get(e.id) || e.id;
    out.remote = remote;
    return out;
  };
}

// ---------------------------------------------------------------- counting
/**
 * Which ports of a public target are kept apart: those open to it from the internet (a range, not every port), and
 * the admin and database ports. The rest are "other ports" (0): a scan touches thousands, and only the total is shown.
 */
function keepPort(open, target, proto, port) {
  if (!open || NOTABLE.has(port)) return true;
  return (open.get(target) || []).some((p) => (p.proto === 'all' || p.proto === proto) && p.ranges && p.ranges.some(([a, b]) => port >= a && port <= b));
}
/** Every AWS public target's open ports, from the analysis: Map(target -> [{ proto, ranges | null for every port }]). */
export function openPorts(exposures = []) {
  return new Map(exposures.filter((e) => e.cloud === 'aws').map((e) => [e.id, e.ports.map((p) => ({ proto: p.proto, ranges: portsIn(p.ports) }))]));
}

function addRecord(r, route, into, { open, vpc } = {}) {
  const x = route(r, vpc); if (!x) return;
  const start = Number(r.start); if (!Number.isFinite(start)) return;
  const hour = Math.floor(start / 3600) * HOUR;
  const bytes = Number(r.bytes) || 0, packets = Number(r.packets) || 0, action = r.action === 'REJECT' ? 'REJECT' : 'ACCEPT';
  // refused traffic counts per line, not per port: only its total is shown
  const port = action === 'REJECT' ? 0 : x.port;
  // between two VPCs whose flow logs are both read, what is accepted is in both: counted where it leaves (from when the
  // other end's flow log was on). A refusal is logged only where it is refused.
  const links = action === 'ACCEPT' && x.inbound && x.remoteSince != null && start * 1000 >= x.remoteSince ? [] : x.links;
  for (const id of links) {
    const key = `${hour}|${id}|${x.side}|${x.dir}|${port}|${x.proto}|${action}`;
    let row = into.links.get(key);
    if (!row) into.links.set(key, row = { hour, link: id, side: x.side, dir: x.dir, port, proto: x.proto, action, bytes: 0, packets: 0, records: 0 });
    row.bytes += bytes; row.packets += packets; row.records++;
  }
  if (x.exposure) {
    const ep = keepPort(open, x.exposure, x.proto, x.port) ? x.port : 0;
    const key = `${hour}|${x.exposure}|${ep}|${x.proto}|${action}`;
    let row = into.exposure.get(key);
    if (!row) into.exposure.set(key, row = { hour, target: x.exposure, port: ep, proto: x.proto, action, bytes: 0, records: 0, sources: new Set() });
    row.bytes += bytes; row.records++; if (row.sources.size < 5000) row.sources.add(x.remote);
  }
}

/** Totals of a batch of records: { links: Map(key -> row), exposure: Map(key -> row with sources Set) }; `hour` in ms. */
export function aggregate(records, route, into = { links: new Map(), exposure: new Map() }, opts = {}) {
  for (const r of records) addRecord(r, route, into, opts);
  return into;
}
function mergeInto(into, from) {
  for (const [k, r] of from.links) { const t = into.links.get(k); if (!t) into.links.set(k, r); else { t.bytes += r.bytes; t.packets += r.packets; t.records += r.records; } }
  for (const [k, r] of from.exposure) {
    const t = into.exposure.get(k); if (!t) { into.exposure.set(k, r); continue; }
    t.bytes += r.bytes; t.records += r.records; for (const s of r.sources) { if (t.sources.size >= 5000) break; t.sources.add(s); }
  }
}
/**
 * Past `keep` ports on one line, side, direction and protocol in an hour, the quietest fold into port 0 ("other
 * ports"): traffic between two high ports (RTP, NodePorts, passive FTP) is counted, but not row by row.
 */
export function foldPorts(links, keep = PORTS_KEPT) {
  const groups = new Map();
  for (const [k, row] of links) {
    if (!row.port) continue;
    const g = `${row.hour}|${row.link}|${row.side}|${row.dir}|${row.proto}|${row.action}`;
    (groups.get(g) || groups.set(g, []).get(g)).push([k, row]);
  }
  for (const rows of groups.values()) {
    if (rows.length <= keep) continue;
    rows.sort((a, b) => b[1].bytes - a[1].bytes || b[1].records - a[1].records);
    for (const [k, row] of rows.slice(keep)) {
      links.delete(k);
      const k0 = `${row.hour}|${row.link}|${row.side}|${row.dir}|0|${row.proto}|${row.action}`;
      let t = links.get(k0); if (!t) links.set(k0, t = { ...row, port: 0, bytes: 0, packets: 0, records: 0 });
      t.bytes += row.bytes; t.packets += row.packets; t.records += row.records;
    }
  }
  return links;
}

async function saveBatch(agg, files) {
  const L = [...foldPorts(agg.links).values()], E = [...agg.exposure.values()];
  await tx(async (c) => {
    for (let i = 0; i < L.length; i += 1000) {
      const p = L.slice(i, i + 1000);
      await c.query(`INSERT INTO net_flow_hourly(hour, link_id, side, dir, port, proto, action, bytes, packets, records)
        SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::text[], $4::text[], $5::int[], $6::text[], $7::text[], $8::bigint[], $9::bigint[], $10::bigint[])
        ON CONFLICT (hour, link_id, side, dir, port, proto, action) DO UPDATE SET bytes = net_flow_hourly.bytes + EXCLUDED.bytes, packets = net_flow_hourly.packets + EXCLUDED.packets, records = net_flow_hourly.records + EXCLUDED.records`,
      [p.map((x) => new Date(x.hour)), p.map((x) => x.link), p.map((x) => x.side), p.map((x) => x.dir), p.map((x) => x.port), p.map((x) => x.proto), p.map((x) => x.action), p.map((x) => x.bytes), p.map((x) => x.packets), p.map((x) => x.records)]);
    }
    for (let i = 0; i < E.length; i += 1000) {
      const p = E.slice(i, i + 1000);
      await c.query(`INSERT INTO net_flow_exposure(hour, target, port, proto, action, records, bytes, sources)
        SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::int[], $4::text[], $5::text[], $6::bigint[], $7::bigint[], $8::int[])
        ON CONFLICT (hour, target, port, proto, action) DO UPDATE SET records = net_flow_exposure.records + EXCLUDED.records, bytes = net_flow_exposure.bytes + EXCLUDED.bytes, sources = GREATEST(net_flow_exposure.sources, EXCLUDED.sources)`,
      [p.map((x) => new Date(x.hour)), p.map((x) => x.target), p.map((x) => x.port), p.map((x) => x.proto), p.map((x) => x.action), p.map((x) => x.records), p.map((x) => x.bytes), p.map((x) => x.sources.size)]);
    }
    await c.query(`INSERT INTO net_flow_files(bucket, key, flow_log, owner, vpc_node, file_time, size, records)
      SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::bigint[], $8::int[]) ON CONFLICT DO NOTHING`,
    [files.map((f) => f.bucket), files.map((f) => f.key), files.map((f) => f.flowLog), files.map((f) => f.owner), files.map((f) => f.vpcNode), files.map((f) => new Date(f.time)), files.map((f) => f.size), files.map((f) => f.records)]);
  });
}

// ---------------------------------------------------------------- which flow logs are read
const TRAFFIC_RANK = { ALL: 0, ACCEPT: 1, REJECT: 1 };
const kindsOf = (fl) => (fl.data.traffic === 'ACCEPT' ? ['ACCEPT'] : fl.data.traffic === 'REJECT' ? ['REJECT'] : ['ACCEPT', 'REJECT']);
/** From when a flow log's history is read: the lookback, or since it was turned on. */
export const historyFrom = (fl, now = Date.now()) => Math.max(now - LOOKBACK_DAYS * DAY, fl?.data?.created ? new Date(fl.data.created).getTime() - HOUR : 0);

/**
 * Which flow logs are read: those delivered to S3 as plain text, on a VPC, a subnet or a network interface, in a
 * format that says where traffic went. Of those, one per VPC (or subnet, or interface) and kind of traffic (all, or
 * accepted and rejected apart): a VPC's own before a subnet's or an interface's in it, one being read before another,
 * one that reads before one that fails, all traffic before part of it, the oldest first. The rest get a note, as
 * reading two that log the same records would count them twice. `states`: net_flow_reads rows by flow log.
 * → { read: [{ fl, vpcNode, dest, covers, info }], skip: [{ fl, vpcNode, dest, note }] }
 */
export function planFlowLogs(fls, items, states = new Map()) {
  const byId = (type) => new Map(items.filter((i) => i.cloud === 'aws' && i.type === type).map((i) => [i.id, i]));
  const subnets = byId('subnet'), enis = byId('eni');
  const vpcNodeOf = (fl) => {
    if (fl.vpc) return `aws:vpc:${fl.vpcOwner || fl.owner}:${fl.vpc}`;
    const r = fl.data.resource || '', x = r.startsWith('subnet-') ? subnets.get(r) : r.startsWith('eni-') ? enis.get(r) : null;
    return x?.vpc ? `aws:vpc:${x.vpcOwner || x.owner}:${x.vpc}` : null;
  };
  const read = [], skip = [], cands = [];
  for (const fl of fls) {
    const vpcNode = vpcNodeOf(fl), res = fl.data.resource || '';
    const level = res.startsWith('vpc-') ? 0 : res.startsWith('subnet-') ? 1 : res.startsWith('eni-') ? 2 : -1;
    const dest = s3Dest(fl.data.arn);
    const no = (note) => skip.push({ fl, vpcNode, dest, note });
    if (fl.data.destination !== 's3') { no(`delivered to ${{ 'cloud-watch-logs': 'CloudWatch Logs', 'kinesis-data-firehose': 'Amazon Data Firehose' }[fl.data.destination] || fl.data.destination || 'somewhere else'}; only S3 is read`); continue; }
    if (fl.data.fileFormat === 'parquet') { no('Parquet files are not read yet; plain text only'); continue; }
    if (!dest) { no('no S3 destination'); continue; }
    if (level < 0) { no(`a ${/^tgw-attach-/.test(res) ? 'transit gateway attachment' : /^tgw-/.test(res) ? 'transit gateway' : 'resource'} flow log: only VPC, subnet and network interface flow logs say which line traffic used`); continue; }
    const missing = fl.data.format ? NEED.filter((c) => !fieldsOf(fl.data.format).includes(c)) : [];
    if (missing.length) { no(`its log format leaves out ${missing.join(', ')}: without them a record cannot be put on a line`); continue; }
    cands.push({ fl, vpcNode, level, dest: { ...dest, account: fl.owner, region: fl.region, hive: !!fl.data.hive, perHour: !!fl.data.perHour } });
  }
  const st = (c) => states.get(c.fl.id);
  const working = (c) => (st(c)?.front && !st(c)?.error && st(c)?.status !== 'skipped' ? 0 : 1);
  cands.sort((a, b) => a.level - b.level || working(a) - working(b) || (st(a)?.error ? 1 : 0) - (st(b)?.error ? 1 : 0)
    || (TRAFFIC_RANK[a.fl.data.traffic] ?? 0) - (TRAFFIC_RANK[b.fl.data.traffic] ?? 0)
    || String(a.fl.data.created || '9').localeCompare(String(b.fl.data.created || '9')) || a.fl.id.localeCompare(b.fl.id));
  const taken = new Map();   // VPC node, subnet or interface -> kind of traffic -> the flow log read for it
  for (const c of cands) {
    const res = c.fl.data.resource, kinds = kindsOf(c.fl);
    // a VPC's flow log has its subnets' and interfaces' records; a subnet's, its interfaces'
    const scopes = [c.vpcNode, c.level >= 1 && res, c.level === 2 && enis.get(res)?.data.subnet].filter(Boolean);
    const by = scopes.flatMap((s) => kinds.map((x) => taken.get(s)?.[x])).find(Boolean);
    const what = ["this VPC's", "this subnet's", "this network interface's"][c.level];
    if (by) { skip.push({ fl: c.fl, vpcNode: c.vpcNode, dest: c.dest, note: `not read: ${by.id} already logs ${what} traffic, and reading both would count it twice` }); continue; }
    const own = c.level === 0 ? c.vpcNode : res;
    if (own) { const t = taken.get(own) || taken.set(own, {}).get(own); for (const x of kinds) t[x] = c.fl; }
    const info = [c.fl.data.traffic === 'REJECT' ? 'keeps rejected traffic only: refusals are counted, but it cannot show that a line is unused'
      : c.level > 0 ? `a ${c.level === 1 ? 'subnet' : 'network interface'} flow log: its traffic is counted, but only a VPC's own flow log can show that a line is unused` : null,
    c.fl.data.deliverStatus === 'FAILED' ? `AWS says delivery fails: ${c.fl.data.deliverError || 'no reason given'}` : null].filter(Boolean).join(' · ') || null;
    read.push({ fl: c.fl, vpcNode: c.vpcNode, dest: c.dest, covers: c.level === 0 && c.fl.data.traffic !== 'REJECT', info });
  }
  return { read, skip };
}

// ---------------------------------------------------------------- reading state
const ms = (d) => (d ? new Date(d).getTime() : null);
const DENIED = /AccessDenied|not authorized|Forbidden|403|KMS/i;
async function noteSkip(s) {
  await query(`INSERT INTO net_flow_reads(flow_log, owner, vpc_node, bucket, prefix, note, status, read_at, created) VALUES ($1,$2,$3,$4,$5,$6,'skipped', now(), $7)
    ON CONFLICT (flow_log) DO UPDATE SET owner = EXCLUDED.owner, vpc_node = EXCLUDED.vpc_node, bucket = EXCLUDED.bucket, prefix = EXCLUDED.prefix, note = EXCLUDED.note,
      status = 'skipped', pending = 0, read_at = now(), created = EXCLUDED.created, covers = false`,
  [s.fl.id, s.fl.owner, s.vpcNode, s.dest?.bucket ?? null, s.dest?.prefix ?? null, s.note, s.fl.data.created || null]);
}
async function saveRead(j) {
  const e = j.error;
  const error = !e ? null : DENIED.test(`${e.name} ${e.message}`) ? `not allowed to read s3://${j.dest.bucket}/${j.dest.prefix ? `${j.dest.prefix}/` : ''}AWSLogs/…/vpcflowlogs/ as ${j.reader.name}: ${String(e.message).slice(0, 200)}` : String(e.message).slice(0, 300);
  // its listing vouches for an idle VPC only when it is the VPC's own of accepted traffic and AWS does not say delivery fails
  const covers = !!j.covers && j.fl.data.deliverStatus !== 'FAILED';
  await query(`INSERT INTO net_flow_reads(flow_log, owner, vpc_node, bucket, prefix, last_time, files, bytes, note, error, read_at, front, back, listed_at, pending, status, created, covers)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now(), $11,$12,$13,$14,'read',$15,$16)
    ON CONFLICT (flow_log) DO UPDATE SET owner = EXCLUDED.owner, vpc_node = EXCLUDED.vpc_node, bucket = EXCLUDED.bucket, prefix = EXCLUDED.prefix,
      last_time = GREATEST(net_flow_reads.last_time, EXCLUDED.last_time), files = net_flow_reads.files + EXCLUDED.files, bytes = net_flow_reads.bytes + EXCLUDED.bytes,
      note = EXCLUDED.note, error = EXCLUDED.error, read_at = now(), front = EXCLUDED.front, back = EXCLUDED.back, listed_at = EXCLUDED.listed_at, pending = EXCLUDED.pending, status = 'read',
      created = EXCLUDED.created, covers = EXCLUDED.covers`,
  [j.fl.id, j.fl.owner, j.vpcNode, j.dest.bucket, j.dest.prefix, j.read.last ? new Date(j.read.last) : null, j.read.files, j.read.bytes, j.info, error,
    j.st.front != null ? new Date(j.st.front) : null, j.st.back != null ? new Date(j.st.back) : null, j.st.listedAt != null ? new Date(j.st.listedAt) : null, j.st.pending, j.fl.data.created || null, covers]);
}

/** What the page says about one flow log: whether and how far it is read. `r`: its net_flow_reads row; `fl`: its item, if at hand. */
export function flowState(fl, r, now = Date.now()) {
  const from = historyFrom(fl?.data?.created ? fl : { data: { created: r?.created } }, now), front = ms(r?.front), back = ms(r?.back);
  const state = r?.status === 'skipped' ? 'skipped' : r?.error ? 'error' : front == null ? 'waiting' : r.pending > 0 || back == null || back > from + MINUTE ? 'catching-up' : 'current';
  const days = front != null && back != null ? Math.max(0, (now - Math.max(back, from)) / DAY) : 0;
  return { state, lastTime: r?.last_time || null, back: back != null ? new Date(Math.max(back, from)).toISOString() : null, historyDays: Math.round(Math.min(days, LOOKBACK_DAYS) * 10) / 10,
    pending: r?.pending || 0, files: r?.files || 0, bytes: Number(r?.bytes || 0), note: r?.note || null, error: r?.status === 'skipped' ? null : r?.error || null, readAt: r?.read_at || null };
}

// ---------------------------------------------------------------- reading
const spentFiles = (ctx) => ctx.budget.files <= 0 || ctx.budget.bytes <= 0;
const spent = (ctx) => spentFiles(ctx) || ctx.budget.lists <= 0;
async function listFolder(j, prefix, startAfter, ctx) {
  ctx.out.lists++; ctx.budget.lists--;
  const got = await j.gw.listFlowLogObjects({ bucket: j.dest.bucket, prefix, ...(startAfter ? { startAfter } : {}) });
  return got.map((o) => ({ key: o.key, size: o.size || 0, time: fileTime(o.key) })).filter((o) => o.time != null);
}
async function unread(bucket, keys) {
  if (!keys.length) return [];
  const done = new Set((await query('SELECT key FROM net_flow_files WHERE bucket = $1 AND key = ANY($2)', [bucket, keys.map((x) => x.key)])).rows.map((r) => r.key));
  return keys.filter((x) => !done.has(x.key));
}
/**
 * Read files in the order given, a few at a time, while the budget lasts; each file is counted on its own and kept
 * only when whole. → how many from the start of the list are read (the rest wait for the next step).
 */
async function readFiles(j, todo, ctx) {
  const ok = [], batch = { links: new Map(), exposure: new Map() }, files = [];
  let next = 0, failed = null;
  const take = () => {
    if (failed || j.missing || next >= todo.length || spentFiles(ctx)) return -1;
    ctx.budget.files--; ctx.budget.bytes -= todo[next].size;
    return next++;
  };
  const worker = async () => {
    for (let i = take(); i >= 0; i = take()) {
      const o = todo[i];
      let buf;
      try { buf = await j.gw.getFlowLogObject({ bucket: j.dest.bucket, key: o.key }); } catch (e) { failed ||= e; continue; }
      const one = { links: new Map(), exposure: new Map() };
      let r = { records: 0, missing: [] }, whole = true;
      // a broken file is passed over (what it held up to the break is dropped), not read again and again
      try { r = await countFlowFile(buf, ctx.route, one, { open: ctx.open, vpc: j.vpcNode }); } catch (e) { whole = false; ctx.log('warn', 'flow log file not readable', { key: o.key, error: e.message }); }
      if (r.missing.length) j.missing = r.missing; else if (whole) mergeInto(batch, one);
      files.push({ bucket: j.dest.bucket, key: o.key, flowLog: j.fl.id, owner: j.fl.owner, vpcNode: j.covers && whole && !r.missing.length ? j.vpcNode : null, time: o.time, size: buf.length, records: whole ? r.records : 0 });
      ok[i] = true;
      ctx.out.files++; ctx.out.bytes += buf.length; ctx.out.records += r.records; j.read.files++; j.read.bytes += buf.length; j.read.last = Math.max(j.read.last || 0, o.time);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARALLEL, todo.length) }, worker));
  if (files.length) await saveBatch(batch, files);
  if (j.missing && !failed) failed = new Error(`its files leave out ${j.missing.join(', ')}: their records cannot be put on a line`);
  if (failed) j.error = failed;
  let k = 0; while (k < todo.length && ok[k]) k++;
  return k;
}
/** The files of every folder from the one `from` falls in to the present (from `from` on in the first, when resuming). */
async function listFrom(j, from, resume, ctx) {
  const stem = fileStem(j.dest, j.fl.id), out = [];
  for (let f = folderOf(j.dest, from); f.start <= ctx.now; f = folderOf(j.dest, f.end)) {
    out.push(...await listFolder(j, f.prefix + stem, resume && f.start <= from ? `${f.prefix}${stem}${stamp(from)}` : undefined, ctx));
  }
  return out;
}
/** New files: the first time the newest folder, newest first; then on from where it got to, oldest first. */
async function forward(j, ctx) {
  const first = j.st.front == null;
  const from = Math.max(j.since, (first ? ctx.now : j.st.front) - LATE);
  const keys = await listFrom(j, from, !first, ctx);
  j.st.listedAt = ctx.now;
  if (first) {
    const todo = (await unread(j.dest.bucket, keys.filter((o) => o.time >= j.since))).sort((a, b) => b.time - a.time);
    const k = await readFiles(j, todo, ctx);
    if (k === todo.length) { j.st.front = ctx.now; j.st.back = Math.max(j.since, folderOf(j.dest, from).start); }
    else if (k > 0) { j.st.front = ctx.now; j.st.back = todo[k - 1].time + MINUTE; }   // what is older is history
    j.st.pending = 0;
    return;
  }
  const todo = (await unread(j.dest.bucket, keys.filter((o) => o.time >= from))).sort((a, b) => a.time - b.time);
  const k = await readFiles(j, todo, ctx);
  if (k === todo.length) j.st.front = ctx.now; else if (k > 0) j.st.front = todo[k - 1].time;
  j.st.pending = todo.length - k;
}
/**
 * History: the folder just before what is read, newest first. All of it that is not read yet: a file's time and its
 * folder need not agree (the last file of a day can carry the next day's first minutes).
 */
async function backward(j, ctx) {
  const f = folderOf(j.dest, j.st.back - 1);
  const keys = (await listFolder(j, f.prefix + fileStem(j.dest, j.fl.id), undefined, ctx)).filter((o) => o.time >= j.since);
  const todo = (await unread(j.dest.bucket, keys)).sort((a, b) => b.time - a.time);
  const k = await readFiles(j, todo, ctx);
  if (k === todo.length) j.st.back = Math.max(j.since, f.start); else if (k > 0) j.st.back = todo[k - 1].time + MINUTE;
}
async function step(j, fn, ctx) {
  j.touched = true;
  try { await fn(); } catch (e) { j.error ||= e; }
  if (j.error) { ctx.out.errors++; ctx.log('warn', 'flow logs not read', { flowLog: j.fl.id, error: j.error.message }); }
}

let prunedAt = 0;
async function prune() {
  if (Date.now() - prunedAt < HOUR) return;
  prunedAt = Date.now();
  await query(`DELETE FROM net_flow_files WHERE file_time < now() - make_interval(days => $1)`, [KEEP_FILES_DAYS]);
  await query(`DELETE FROM net_flow_hourly WHERE hour < now() - make_interval(days => $1)`, [KEEP_DAYS]);
  await query(`DELETE FROM net_flow_exposure WHERE hour < now() - make_interval(days => $1)`, [KEEP_DAYS]);
}

/**
 * Worker step: read new flow log files, a budget at a time. `gwFor(account row)` gives the gateway that reads a
 * bucket: the account that owns it when it is connected (a log archive account), else the flow log's own account.
 * Only the worker runs it (src/worker.js, every minute), one worker at a time; each step is noted in worker_steps
 * with the worker that ran it, for Operations and the Networking page. → what it read, or null when nothing.
 */
export async function flowTick({ log = () => {}, gwFor = null, now = Date.now(), analyze, worker = null } = {}) {
  if (!(await isEnabled('networking'))) return null;
  const client = await pool.connect();
  try {
    if (!(await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK])).rows[0].ok) return null;   // another worker is reading
    const started = Date.now();
    let out = null, error = null;
    try {
      out = await readFlowLogs({ log, gwFor, now, analyze });
      return out && (out.files || out.errors) ? out : null;
    } catch (e) { error = e; throw e; } finally {
      await noteStep(FLOW_STEP, { worker, started, out, error }).catch((e) => log('warn', 'flow log step not noted', { error: e.message }));
      await client.query('SELECT pg_advisory_unlock($1)', [LOCK]);
    }
  } finally { client.release(); }
}
export const FLOW_STEP = 'vpc-flow-logs';
async function noteStep(step, { worker, started, out, error }) {
  const did = !!(error || out?.files || out?.errors);
  const result = { files: 0, bytes: 0, records: 0, errors: 0, lists: 0, ...(out || {}) };
  await query(`INSERT INTO worker_steps(step, worker_id, started_at, finished_at, ms, error, result, runs, worked_at, work)
    VALUES ($1, $2, $3, now(), $4, $5, $6::jsonb, 1, CASE WHEN $7::boolean THEN now() END, CASE WHEN $7::boolean THEN $6::jsonb END)
    ON CONFLICT (step) DO UPDATE SET worker_id = EXCLUDED.worker_id, started_at = EXCLUDED.started_at, finished_at = now(), ms = EXCLUDED.ms, error = EXCLUDED.error, result = EXCLUDED.result,
      runs = worker_steps.runs + 1, worked_at = COALESCE(EXCLUDED.worked_at, worker_steps.worked_at), work = COALESCE(EXCLUDED.work, worker_steps.work)`,
  [step, worker, new Date(started), Date.now() - started, error ? String(error.message || error).slice(0, 300) : null, JSON.stringify(result), did]);
}
/**
 * The reader's last step, and the worker that ran it: { at, ms, error, result, workedAt, work, runs, worker: { id,
 * hostname, alive } } or null before the first. Operations and the Networking page both say it.
 */
export async function flowStep() {
  const r = (await query(`SELECT s.*, w.hostname, (w.stopped_at IS NULL AND w.heartbeat_at > now() - interval '60 seconds') AS alive
    FROM worker_steps s LEFT JOIN workers w ON w.id = s.worker_id WHERE s.step = $1`, [FLOW_STEP])).rows[0];
  const anyAlive = (await query(`SELECT count(*)::int AS n FROM workers WHERE stopped_at IS NULL AND heartbeat_at > now() - interval '60 seconds'`)).rows[0].n;
  return { workersAlive: anyAlive, last: r ? { at: r.finished_at, startedAt: r.started_at, ms: r.ms, error: r.error, result: r.result, workedAt: r.worked_at, work: r.work, runs: Number(r.runs),
    worker: { id: r.worker_id, hostname: r.hostname || null, alive: !!r.alive } } : null };
}

async function readFlowLogs({ log, gwFor, now, analyze }) {
  const { loadItems, networkEstate } = await import('./sync.js');
  const { analyzeNetwork } = await import('./analyze.js');
  const items = await loadItems(), shared = shareAware(items).items;
  const fls = shared.filter((i) => i.cloud === 'aws' && i.type === 'flow-log' && i.data.status === 'ACTIVE');
  // a flow log deleted, turned off, or in an account no longer read leaves the list
  await query('DELETE FROM net_flow_reads WHERE NOT (flow_log = ANY($1))', [fls.map((f) => f.id)]);
  await prune();
  if (!fls.length) return null;
  const states = new Map((await query('SELECT * FROM net_flow_reads')).rows.map((r) => [r.flow_log, r]));
  const plan = planFlowLogs(fls, shared, states);
  for (const s of plan.skip) { const cur = states.get(s.fl.id); if (cur?.status !== 'skipped' || cur.note !== s.note || cur.vpc_node !== s.vpcNode) await noteSkip(s); }
  if (!plan.read.length) return null;

  const a = (analyze || analyzeNetwork)(items, await networkEstate());
  const logged = new Map(plan.read.filter((p) => p.covers && p.vpcNode && !states.get(p.fl.id)?.error).map((p) => [p.vpcNode, p.fl.data.created ? new Date(p.fl.data.created).getTime() : -Infinity]));
  const ctx = { now, log, route: flowRouter(items, a.graph, { logged }), open: openPorts(a.exposures), out: { files: 0, bytes: 0, records: 0, errors: 0, lists: 0 },
    budget: { files: BUDGET_FILES, bytes: BUDGET_BYTES, lists: BUDGET_LISTS } };
  const byAcct = new Map((await query('SELECT * FROM cloud_accounts')).rows.map((x) => [x.account_id, x]));
  const bucketOwner = new Map((await query(`SELECT r.name, a.account_id FROM resources r JOIN cloud_accounts a ON a.id = r.account_id WHERE r.service = 's3' AND r.deleted_at IS NULL`).catch(() => ({ rows: [] }))).rows.map((r) => [r.name, r.account_id]));
  if (!gwFor) { const workspace = (await query('SELECT * FROM workspace')).rows[0]; gwFor = (x) => getGateway(x, workspace); }
  const gws = new Map(), jobs = [];
  for (const p of plan.read) {
    const cur = states.get(p.fl.id);
    const j = { ...p, reader: byAcct.get(bucketOwner.get(p.dest.bucket)) || byAcct.get(p.fl.owner), since: historyFrom(p.fl, now), read: { files: 0, bytes: 0, last: null },
      st: { front: ms(cur?.front), back: ms(cur?.back), listedAt: ms(cur?.listed_at), pending: cur?.pending || 0 } };
    if (!j.reader) continue;
    // one that could not be read waits a while before it is tried again
    if (cur?.error && cur.status === 'read' && now - ms(cur.read_at) < RETRY_EVERY) continue;
    if (!gws.has(j.reader.id)) gws.set(j.reader.id, Promise.resolve().then(() => gwFor(j.reader)));
    try { j.gw = await gws.get(j.reader.id); } catch (e) { j.error = e; ctx.out.errors++; await saveRead(j); continue; }
    if (j.gw.listFlowLogObjects) jobs.push(j);
  }
  // new files first, for every flow log; the one listed longest ago first, so a short budget goes round
  const due = (j) => j.st.front == null || j.st.pending > 0 || j.st.listedAt == null || now - j.st.listedAt >= LIST_EVERY;
  for (const j of jobs.filter(due).sort((x, y) => (x.st.front == null ? 0 : 1) - (y.st.front == null ? 0 : 1) || (x.st.listedAt ?? 0) - (y.st.listedAt ?? 0))) {
    if (spent(ctx)) break;
    await step(j, () => forward(j, ctx), ctx);
  }
  // then history, a folder at a time in turns, the one with the least read first
  const hist = jobs.filter((j) => !j.error && j.st.back != null && j.st.back > j.since).sort((x, y) => y.st.back - x.st.back);
  for (let i = 0; hist.length && !spent(ctx);) {
    const j = hist[i];
    await step(j, () => backward(j, ctx), ctx);
    if (j.error || j.st.back <= j.since) hist.splice(i, 1); else i++;
    if (i >= hist.length) i = 0;
  }
  for (const j of jobs) if (j.touched) await saveRead(j);
  if (ctx.out.files) log('info', 'flow logs read', ctx.out);
  return ctx.out;
}

// ---------------------------------------------------------------- what the flow logs say
/** Bytes and refusals on each line by the hour, the 24 hours from `hourStart`: Map(link -> [24 × { bytes, rejected }]). */
export async function loadHours(hourStart) {
  const rows = (await query(`SELECT link_id, hour, sum(bytes) FILTER (WHERE action = 'ACCEPT')::bigint AS bytes, sum(records) FILTER (WHERE action = 'REJECT')::bigint AS rejected
    FROM net_flow_hourly WHERE hour >= to_timestamp($1) AND hour < to_timestamp($2) GROUP BY 1, 2`, [hourStart / 1000, (hourStart + DAY) / 1000])).rows;
  const out = new Map();
  for (const r of rows) {
    const x = out.get(r.link_id) || out.set(r.link_id, Array.from({ length: 24 }, () => ({ bytes: 0, rejected: 0 }))).get(r.link_id);
    const b = Math.max(0, Math.min(23, Math.floor((new Date(r.hour).getTime() - hourStart) / HOUR)));
    x[b].bytes += Number(r.bytes || 0); x[b].rejected += Number(r.rejected || 0);
  }
  return out;
}

/** How much the flow log tables take in the database, in bytes. */
export async function flowStorage() {
  return Number((await query(`SELECT coalesce(sum(pg_total_relation_size(c)), 0)::bigint AS n FROM unnest(ARRAY['net_flow_hourly', 'net_flow_exposure', 'net_flow_files', 'net_flow_reads']::regclass[]) c`)).rows[0].n);
}

/**
 * What the flow logs say, for the analyzer and the page: per line, accepted and rejected traffic over `days` (and
 * the last 24 hours by the hour from `hourStart`); per VPC, how far back its flow logs were read; per public target and
 * port, what the internet reached.
 */
export async function loadUsage({ days = LOOKBACK_DAYS, hourStart = null } = {}) {
  const [links, cover, exp, hourly, ports, seen] = await Promise.all([
    query(`SELECT link_id, sum(bytes) FILTER (WHERE action = 'ACCEPT')::bigint AS bytes, sum(records) FILTER (WHERE action = 'ACCEPT')::bigint AS flows,
             sum(records) FILTER (WHERE action = 'REJECT')::bigint AS rejected, max(hour) FILTER (WHERE action = 'ACCEPT') AS last
             FROM net_flow_hourly WHERE hour >= now() - make_interval(days => $1) GROUP BY 1`, [days]),
    query(`SELECT vpc_node, min(file_time) AS since, max(file_time) AS until, count(*)::int AS files FROM net_flow_files WHERE vpc_node IS NOT NULL AND file_time >= now() - make_interval(days => $1) GROUP BY 1`, [days]),
    query(`SELECT target, port, proto, sum(records) FILTER (WHERE action = 'ACCEPT')::bigint AS accepted, sum(records) FILTER (WHERE action = 'REJECT')::bigint AS rejected, max(sources)::int AS sources
             FROM net_flow_exposure WHERE hour >= now() - make_interval(days => $1) GROUP BY 1, 2, 3`, [days]),
    hourStart != null ? loadHours(hourStart) : new Map(),
    query(`SELECT link_id, port, proto, sum(bytes)::bigint AS bytes FROM net_flow_hourly WHERE action = 'ACCEPT' AND hour >= now() - make_interval(days => $1) GROUP BY 1, 2, 3`, [days]),
    // how far a VPC's own flow log was listed, everything found read: an idle VPC writes no files, and is still covered
    query(`SELECT vpc_node, max(front) AS front FROM net_flow_reads WHERE status = 'read' AND covers AND error IS NULL AND front IS NOT NULL AND vpc_node IS NOT NULL GROUP BY 1`).catch(() => ({ rows: [] })),
  ]);
  const L = new Map(links.rows.map((r) => [r.link_id, { bytes: Number(r.bytes || 0), flows: Number(r.flows || 0), rejected: Number(r.rejected || 0), last: r.last, ports: [], hourly: null }]));
  for (const r of ports.rows) L.get(r.link_id)?.ports.push({ port: r.port, proto: r.proto, bytes: Number(r.bytes) });
  for (const x of L.values()) { x.ports.sort((a, b) => b.bytes - a.bytes); x.ports = x.ports.slice(0, 8); }
  for (const [id, h] of hourly) (L.get(id) || L.set(id, { bytes: 0, flows: 0, rejected: 0, last: null, ports: [] }).get(id)).hourly = h;
  const front = new Map(seen.rows.map((r) => [r.vpc_node, new Date(r.front).getTime()]));
  // covered up to the newest file, or as far as the listing found nothing more: up to 48 hours past that file (a
  // delivery that broke without AWS saying so cannot vouch for longer)
  const C = new Map(cover.rows.map((r) => {
    const last = new Date(r.until).getTime(), listed = front.get(r.vpc_node);
    return [r.vpc_node, { since: r.since, until: listed > last ? new Date(Math.min(listed, last + VOUCH)) : r.until, files: r.files, newest: r.until }];
  }));
  const E = new Map();
  for (const r of exp.rows) { if (!E.has(r.target)) E.set(r.target, new Map()); E.get(r.target).set(`${r.proto}|${r.port}`, { accepted: Number(r.accepted || 0), rejected: Number(r.rejected || 0), sources: r.sources || 0 }); }
  return { links: L, coverage: C, exposure: E, days };
}
