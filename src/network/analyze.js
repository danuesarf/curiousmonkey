// The network analyzer: from what the reader stored (src/network/awsReader.js, gcpReader.js) to
//   - findings: admin, database or every port open to the internet (security groups, firewall rules, network
//     firewall policies), default networks and VPCs, missing flow logs, public subnets that hand out public IPs, network
//     ACLs that let the internet in, peering and transit gateway attachments with accounts or projects that are not
//     yours, VPN tunnels down, overlapping address ranges between networks that are connected;
//   - exposure: what the internet can reach, address by address and port by port;
//   - the graph: VPCs and networks, transit gateways, the internet and VPN peers as nodes; peering, transit gateway
//     attachments, VPNs (AWS to Google Cloud matched by their tunnel addresses), Interconnect and the internet as links.
// No I/O: src/network/sync.js gives it the items and the estate.
import { severityOf, DEFAULT_POLICY } from '../controlCatalog.js';

const WORLD = new Set(['0.0.0.0/0', '::/0']);
export const ADMIN_PORTS = { 22: 'SSH', 3389: 'RDP', 23: 'Telnet', 5985: 'WinRM', 5986: 'WinRM', 5900: 'VNC', 2375: 'Docker API', 2376: 'Docker API', 10250: 'kubelet' };
export const DATA_PORTS = { 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'SQL Server', 1521: 'Oracle', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch', 5601: 'Kibana',
  11211: 'Memcached', 2379: 'etcd', 9092: 'Kafka', 5984: 'CouchDB', 9042: 'Cassandra', 8086: 'InfluxDB' };
const SEV = { high: 0, medium: 1, low: 2, none: 3 };
export const worstOf = (list) => list.reduce((w, x) => (SEV[x] < SEV[w] ? x : w), 'none');

// ---------------------------------------------------------------- addresses and ports
const ip4 = (s) => { const p = String(s).split('.').map(Number); return p.length === 4 && p.every((x) => x >= 0 && x <= 255) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null; };
/** [start, end] of an IPv4 CIDR, or null. */
export function range4(cidr) {
  const [a, b] = String(cidr || '').split('/'); const base = ip4(a), bits = b == null ? 32 : Number(b);
  if (base == null || !(bits >= 0 && bits <= 32)) return null;
  const size = 2 ** (32 - bits), start = Math.floor(base / size) * size;
  return [start, start + size - 1];
}
export const overlaps = (a, b) => { const x = range4(a), y = range4(b); return !!(x && y && x[0] <= y[1] && y[0] <= x[1]); };
const inCidr = (ip, cidr) => { const r = range4(cidr), v = ip4(ip); return !!(r && v != null && v >= r[0] && v <= r[1]); };

/** Port ranges a rule opens, as [from, to] pairs; null = every port (all protocols, or tcp/udp with no ports). */
function awsPorts(r) { if (r.proto === 'all' || r.from == null || (r.from <= 0 && r.to >= 65535) || r.from === -1) return r.proto === 'icmp' || r.proto === 'icmpv6' ? [] : null; if (!['tcp', 'udp'].includes(r.proto)) return []; return [[r.from, r.to]]; }
function gcpPorts(rules) {
  const out = [];
  for (const x of rules) {
    const p = String(x.proto).toLowerCase();
    if (p === 'all') return null;
    if (!['tcp', 'udp', 'sctp', '6', '17'].includes(p)) continue;
    if (!x.ports?.length) return null;
    for (const s of x.ports) { if (s === 'all') return null; const [a, b] = String(s).split('-').map(Number); out.push([a, b ?? a]); }
  }
  return out;
}
const covers = (ranges, port) => ranges === null || ranges.some(([a, b]) => port >= a && port <= b);
const portText = (ranges) => (ranges === null ? 'every port' : ranges.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(', '));
const span = (ranges) => (ranges === null ? 65536 : ranges.reduce((n, [a, b]) => n + (b - a + 1), 0));
/** What an open range lets in: admin ports, data ports, every port, a wide range, or only other ports. */
export function classifyPorts(ranges) {
  const admin = Object.keys(ADMIN_PORTS).map(Number).filter((p) => covers(ranges, p));
  const data = Object.keys(DATA_PORTS).map(Number).filter((p) => covers(ranges, p));
  return { all: ranges === null, admin, data, wide: ranges !== null && span(ranges) > 1000, text: portText(ranges) };
}
const named = (ports, dict) => [...new Set(ports.map((p) => `${dict[p]} (${p})`))].join(', ');

/**
 * Everything the analyzer needs to know about the estate:
 *   awsAccounts: Map(12-digit -> { id, name }) connected; orgAccounts: Map(12-digit -> name); vendor(acct) -> name|null
 *   gcpProjects: Map(projectId -> { name }) read; ownProject(projectId) -> true when it is yours but not read
 */
export function analyzeNetwork(items, estate = {}, policy = DEFAULT_POLICY) {
  const awsAccounts = estate.awsAccounts || new Map(), orgAccounts = estate.orgAccounts || new Map(), gcpProjects = estate.gcpProjects || new Map();
  const ownAws = (a) => awsAccounts.has(a) || orgAccounts.has(a);
  const awsName = (a) => awsAccounts.get(a)?.name || orgAccounts.get(a) || estate.vendor?.(a) || null;
  const ownGcp = (p) => gcpProjects.has(p) || !!estate.ownProject?.(p);
  const findings = [], exposures = [];
  const f = (control, builtIn, it, title, detail, suggestion, extra = {}) => {
    const severity = severityOf(policy, control, builtIn); if (!severity) return;
    findings.push({ key: `${control}|${it.cloud}|${it.owner}|${extra.keyPart || it.id}`.slice(0, 500), control, severity, cloud: it.cloud, owner: it.owner, itemType: it.type, nativeId: it.id,
      itemName: it.name, vpc: it.vpc, region: it.region || null, title, detail, suggestion });
  };

  // ---------------------------------------------------------------- AWS
  const aws = items.filter((i) => i.cloud === 'aws');
  const by = (type) => aws.filter((i) => i.type === type);
  const key = (owner, id) => `${owner}|${id}`;
  const vpcs = new Map(by('vpc').map((v) => [key(v.owner, v.id), v]));
  const rts = by('route-table'), subnets = by('subnet'), enis = by('eni'), sgs = by('sg'), nacls = by('nacl');
  // a subnet's route table: its own association, else the VPC's main table
  const rtOf = new Map();
  for (const t of rts) for (const s of t.data.subnets) rtOf.set(key(t.owner, s), t);
  const mainRt = new Map(rts.filter((t) => t.data.main).map((t) => [key(t.owner, t.vpc), t]));
  const tableOf = (s) => rtOf.get(key(s.owner, s.id)) || mainRt.get(key(s.owner, s.vpc)) || null;
  const toInternet = (t) => !!t?.data.routes.some((r) => (r.dest === '0.0.0.0/0' || r.dest === '::/0') && (r.target.type === 'igw') && r.state !== 'blackhole');
  const publicSubnet = new Map(subnets.map((s) => [key(s.owner, s.id), toInternet(tableOf(s))]));
  // which interfaces use each group, and whether any of them has a public address
  const users = new Map();
  for (const n of enis) for (const g of n.data.groups) { const k = key(n.owner, g); if (!users.has(k)) users.set(k, []); users.get(k).push(n); }
  const lbs = by('lb');
  for (const b of lbs) for (const g of b.data.groups) { const k = key(b.owner, g); if (!users.has(k)) users.set(k, []); users.get(k).push({ lb: b, data: { publicIp: b.data.scheme === 'internet-facing' ? 'load balancer' : null } }); }
  const reach = (owner, sgId) => { const u = users.get(key(owner, sgId)) || []; return { used: u.length, public: u.some((x) => x.data.publicIp || x.data.publicIps?.length) }; };
  const who = (u) => u.map((x) => x.lb ? `load balancer ${x.lb.name}` : x.data.instance ? `${x.data.description && x.data.description !== x.data.instance ? x.data.description : 'instance'} (${x.data.instance})` : x.data.description || x.id).slice(0, 4).join(', ');

  for (const g of sgs) {
    const u = users.get(key(g.owner, g.id)) || [], r = reach(g.owner, g.id);
    const where = r.public ? `attached to ${who(u)}, reachable from the internet` : r.used ? `attached to ${who(u)}, none of them with a public address` : 'not attached to anything today';
    const sev = (hi) => (r.public ? hi : r.used ? 'medium' : 'low');
    let all = false; const admin = new Set(), data = new Set(), wide = [];
    for (const rule of g.data.ingress) {
      if (![...rule.cidrs, ...rule.ipv6].some((c) => WORLD.has(c))) continue;
      const c = classifyPorts(awsPorts(rule));
      if (c.all) all = true;
      c.admin.forEach((p) => admin.add(p)); c.data.forEach((p) => data.add(p));
      if (c.wide && !c.all) wide.push(`${rule.proto} ${c.text}`);
    }
    const it = { ...g, cloud: 'aws' }, fix = 'Allow only the addresses that need it (your office or VPN ranges), or reach it through Session Manager, a load balancer or a VPN instead.';
    if (all) f('net.sg-all-open', sev('high'), it, `Security group ${g.name} lets the internet in on every port`, `An inbound rule allows all traffic from 0.0.0.0/0; ${where}.`, fix, { keyPart: `${g.id}|all` });
    else {
      if (admin.size) f('net.sg-admin-open', sev('high'), it, `Security group ${g.name} opens ${named([...admin], ADMIN_PORTS)} to the internet`, `Inbound from 0.0.0.0/0 on ${named([...admin], ADMIN_PORTS)}; ${where}.`, fix, { keyPart: `${g.id}|admin` });
      if (data.size) f('net.sg-data-open', sev('high'), it, `Security group ${g.name} opens ${named([...data], DATA_PORTS)} to the internet`, `Inbound from 0.0.0.0/0 on ${named([...data], DATA_PORTS)}; ${where}. A database or cache should never take connections from the internet.`, fix, { keyPart: `${g.id}|data` });
      if (wide.length && !admin.size && !data.size) f('net.sg-wide-open', r.public ? 'medium' : 'low', it, `Security group ${g.name} opens a wide port range to the internet`, `Inbound from 0.0.0.0/0 on ${wide.join('; ')}; ${where}.`, 'Open only the ports the service listens on.', { keyPart: `${g.id}|wide` });
    }
    if (!g.data.isDefault && !r.used) f('net.sg-unused', 'low', it, `Security group ${g.name} is not used`, 'No network interface or load balancer uses it.', 'Delete it, so it cannot be attached later by mistake.');
    if (g.data.isDefault && r.used) f('net.default-sg-used', 'low', it, `The default security group of ${g.vpc} is in use`, `Used by ${who(u)}. The default group is shared by anything launched without a group of its own.`, 'Give those resources their own security group and leave the default one with no rules.');
  }
  // network ACLs on public subnets that let the internet in on admin ports (or everything)
  for (const a of nacls) {
    const pubs = a.data.subnets.filter((s) => publicSubnet.get(key(a.owner, s)));
    if (!pubs.length) continue;
    const ingress = a.data.entries.filter((e) => !e.egress).sort((x, y) => x.n - y.n);
    // the first rule that matches a port decides it (CIS 5.1 looks at SSH and RDP)
    const first = (p) => ingress.find((e) => WORLD.has(e.cidr) && (e.proto === 'all' || (e.proto === 'tcp' && p >= (e.from ?? 0) && p <= (e.to ?? 65535))));
    const open = [22, 3389].filter((p) => first(p)?.action === 'allow');
    const everything = open.length === 2 && open.every((p) => first(p).proto === 'all');
    const label = a.data.isDefault ? `The default network ACL of ${a.vpc}` : `Network ACL ${a.name}`;
    if (open.length) f('net.nacl-admin-open', 'low', { ...a, cloud: 'aws' }, `${label} lets the internet reach ${everything ? 'every port' : named(open, ADMIN_PORTS)} in public subnets`,
      `It allows 0.0.0.0/0 ${everything ? 'on every port, SSH and RDP included,' : `on ${named(open, ADMIN_PORTS)}`} for ${pubs.length} public subnet${pubs.length === 1 ? '' : 's'} (${pubs.slice(0, 4).join(', ')}). Security groups still decide, but nothing backs up a loose one.`, 'Deny 0.0.0.0/0 to SSH (22) and RDP (3389) in the ACL of public subnets (CIS 5.1).');
  }
  // VPCs: default VPC, flow logs, public subnets handing out public addresses
  const flowOn = new Set(by('flow-log').filter((x) => x.data.status === 'ACTIVE').map((x) => key(x.owner, x.data.resource)));
  const enisIn = new Map(); for (const n of enis) enisIn.set(key(n.owner, n.vpc), (enisIn.get(key(n.owner, n.vpc)) || 0) + 1);
  for (const v of vpcs.values()) {
    const it = { ...v, cloud: 'aws' }, inUse = enisIn.get(key(v.owner, v.id)) || 0;
    const subs = subnets.filter((s) => s.owner === v.owner && s.vpc === v.id);
    if (v.data.isDefault) f('net.default-vpc', inUse ? 'medium' : 'low', it, inUse ? `The default VPC in ${v.region} is in use` : `The default VPC in ${v.region} is still there`,
      inUse ? `${inUse} network interface${inUse === 1 ? '' : 's'} sit in it. Its subnets give every instance a public address and its route table sends everything to the internet.` : 'Nothing runs in it, but anything launched without a VPC chosen lands there, with a public address.',
      inUse ? 'Move what runs there into a VPC you designed, then delete the default VPC.' : 'Delete it.');
    if ((!v.data.isDefault || inUse) && !flowOn.has(key(v.owner, v.id)) && !subs.every((s) => flowOn.has(key(v.owner, s.id))))
      f('net.flow-logs-off', 'medium', it, `No flow logs for VPC ${v.name}`, 'Without VPC flow logs nothing records which addresses talked to what: an investigation has nothing to go on.', 'Turn on VPC flow logs (to S3 or CloudWatch Logs), at least for rejected traffic (CIS 3.7).');
    const auto = subs.filter((s) => s.data.mapPublicIp && publicSubnet.get(key(s.owner, s.id)));
    if (auto.length && !v.data.isDefault) f('net.subnet-auto-public-ip', 'low', it, `${auto.length} subnet${auto.length === 1 ? '' : 's'} in ${v.name} give every instance a public address`, `${auto.map((s) => s.name).slice(0, 5).join(', ')} route to an internet gateway and assign public IPs on launch: an instance is on the internet unless someone remembers not to.`, 'Turn off auto-assign public IPv4 and give public addresses only to what needs one.');
  }
  // peering, transit gateways, VPNs
  const peerings = new Map(); for (const p of by('peering')) if (!peerings.has(p.id)) peerings.set(p.id, p);
  for (const p of peerings.values()) {
    const sides = [p.data.requester, p.data.accepter].filter(Boolean), outsider = sides.find((s) => s.account && !ownAws(s.account));
    if (outsider && p.data.status === 'active') {
      const mine = sides.find((s) => s !== outsider);
      f('net.peering-external', 'medium', { ...p, cloud: 'aws', owner: mine?.account || p.owner, vpc: mine?.vpc }, `VPC peering with ${awsName(outsider.account) || `account ${outsider.account}`}, outside your estate`,
        `${p.name} connects ${mine?.vpc} to ${outsider.vpc} (${outsider.cidrs.join(', ') || 'range unknown'}) in account ${outsider.account}. What can cross is decided by route tables and security groups on both sides; theirs you cannot see.`,
        'Confirm the third party still needs it, route only the subnets it needs, and keep security groups on your side tight.');
    }
  }
  const tgws = new Map(by('tgw').map((t) => [t.id, t]));
  const atts = new Map(); for (const a of by('tgw-attachment')) if (!atts.has(a.id)) atts.set(a.id, a);
  for (const a of atts.values()) {
    const tgwOwner = a.data.tgwOwner, resOwner = a.data.resourceOwner;
    const out = [tgwOwner, resOwner].find((x) => x && !ownAws(x));
    if (out && a.data.resourceType !== 'vpn' && a.data.resourceType !== 'direct-connect-gateway')
      f('net.tgw-external', 'medium', { ...a, cloud: 'aws', owner: ownAws(tgwOwner) ? tgwOwner : resOwner }, `Transit gateway attachment with ${awsName(out) || `account ${out}`}, outside your estate`,
        `${a.data.resourceType} ${a.data.resourceId} (account ${resOwner}) is attached to transit gateway ${a.data.tgw} (account ${tgwOwner}). Everything the transit gateway's route tables reach, it can reach.`, 'Confirm it is expected; give it its own transit gateway route table that reaches only what it needs.');
  }
  for (const t of tgws.values()) if (t.data.autoAccept) f('net.tgw-auto-accept', 'low', { ...t, cloud: 'aws' }, `Transit gateway ${t.name} accepts shared attachments on its own`, 'Any account it is shared with can attach a VPC without anyone approving it.', 'Turn off auto accept shared attachments.');
  const cgws = new Map(by('cgw').map((c) => [key(c.owner, c.id), c]));
  for (const v of by('vpn')) {
    const down = v.data.tunnels.filter((t) => t.status !== 'UP');
    if (!down.length || v.data.state !== 'available') continue;
    const allDown = down.length === v.data.tunnels.length, cgw = cgws.get(key(v.owner, v.data.cgw));
    f('net.vpn-down', allDown ? 'medium' : 'low', { ...v, cloud: 'aws' }, allDown ? `VPN ${v.name} is down` : `VPN ${v.name} runs on one tunnel`,
      `${down.length} of ${v.data.tunnels.length} tunnels are down (${down.map((t) => t.outsideIp).join(', ')}), to ${cgw?.name || v.data.cgw} at ${cgw?.data.ip || 'an unknown address'}.${allDown ? '' : ' One more failure and the link is gone.'}`,
      allDown ? 'Check the peer device, or delete the VPN if it is no longer used.' : 'Bring the second tunnel up so maintenance on either side does not cut the link.');
  }

  // exposure: interfaces with a public address and the ports their groups open to the internet; internet-facing load balancers
  const sgById = new Map(sgs.map((g) => [key(g.owner, g.id), g]));
  const worldPorts = (owner, groups) => {
    const out = [];
    for (const gid of groups) { const g = sgById.get(key(owner, gid)); if (!g) continue;
      for (const rule of g.data.ingress) if ([...rule.cidrs, ...rule.ipv6].some((c) => WORLD.has(c))) { const r = awsPorts(rule); if (r && !r.length) continue; out.push({ ranges: r, via: g.name, proto: rule.proto }); } }
    return out;
  };
  const sevPorts = (list) => worstOf(list.map((x) => { const c = classifyPorts(x.ranges); return c.all || c.admin.length || c.data.length ? 'high' : c.wide ? 'medium' : 'low'; }));
  for (const n of enis) {
    const ips = [...new Set([n.data.publicIp, ...(n.data.publicIps || [])].filter(Boolean))];
    if (!ips.length || n.data.kind === 'nat_gateway' || /^ELB /.test(n.data.description || '')) continue;
    const open = worldPorts(n.owner, n.data.groups);
    exposures.push({ cloud: 'aws', owner: n.owner, vpc: n.vpc, region: n.region, kind: 'interface', id: n.id, name: n.data.instance ? `${n.name !== n.id ? n.name : 'instance'} (${n.data.instance})` : n.name,
      addresses: ips, ports: open.map((x) => ({ proto: x.proto, ports: portText(x.ranges), via: `security group ${x.via}` })), severity: open.length ? sevPorts(open) : 'none' });
  }
  for (const b of lbs.filter((x) => x.data.scheme === 'internet-facing')) {
    const open = b.data.groups.length ? worldPorts(b.owner, b.data.groups) : null;
    const ls = b.data.listeners.filter((l) => !open || open.some((x) => covers(x.ranges, l.port)));
    exposures.push({ cloud: 'aws', owner: b.owner, vpc: b.vpc, region: b.region, kind: 'load-balancer', id: b.id, name: b.name, addresses: [b.data.dns],
      ports: ls.map((l) => ({ proto: String(l.proto).toLowerCase(), ports: String(l.port), via: `listener${b.data.groups.length ? '' : ' (no security group)'}` })),
      severity: worstOf(ls.map((l) => (ADMIN_PORTS[l.port] || DATA_PORTS[l.port] ? 'high' : 'low'))) });
  }

  // ---------------------------------------------------------------- Google Cloud
  const gcp = items.filter((i) => i.cloud === 'gcp');
  const gby = (type) => gcp.filter((i) => i.type === type);
  const networks = new Map(gby('network').map((n) => [n.id, n]));
  const instances = gby('instance');
  const inNet = (path) => instances.filter((i) => i.data.interfaces.some((x) => x.network === path));
  const pubOf = (i) => i.data.interfaces.flatMap((x) => x.natIps);
  const targetsOf = (rule, path) => inNet(path).filter((i) => (!rule.targetTags?.length && !rule.targetServiceAccounts?.length)
    || (rule.targetTags || []).some((t) => i.data.tags.includes(t)) || (rule.targetServiceAccounts || []).some((s) => i.data.serviceAccounts.includes(s)));
  const gfw = (it, rule, ranges, path, label) => {
    const c = classifyPorts(ranges); if (!c.all && !c.admin.length && !c.data.length && !c.wide) return;
    const t = targetsOf(rule, path), pub = t.filter((i) => pubOf(i).length);
    const where = pub.length ? `it reaches ${pub.map((i) => `${i.name} (${pubOf(i).join(', ')})`).slice(0, 4).join(', ')}, with external addresses` : t.length ? `it applies to ${t.map((i) => i.name).slice(0, 4).join(', ')}, none with an external address` : 'no instance it targets runs today';
    const sev = (hi) => (pub.length ? hi : t.length ? 'medium' : 'low');
    const fix = 'Allow only the ranges that need it (Identity-Aware Proxy for SSH: 35.235.240.0/20), or remove the rule.';
    const scope = rule.targetTags?.length ? ` (instances tagged ${rule.targetTags.join(', ')})` : rule.targetServiceAccounts?.length ? ` (instances running as ${rule.targetServiceAccounts.join(', ')})` : ' (every instance in the network)';
    if (c.all) f('net.gcp-fw-all-open', sev('high'), it, `${label} lets the internet in on every port`, `Ingress from 0.0.0.0/0 on every protocol and port${scope}; ${where}.`, fix, { keyPart: `${it.id}|all` });
    else {
      if (c.admin.length) f('net.gcp-fw-admin-open', sev('high'), it, `${label} opens ${named(c.admin, ADMIN_PORTS)} to the internet`, `Ingress from 0.0.0.0/0 on ${named(c.admin, ADMIN_PORTS)}${scope}; ${where}.`, fix, { keyPart: `${it.id}|admin` });
      if (c.data.length) f('net.gcp-fw-data-open', sev('high'), it, `${label} opens ${named(c.data, DATA_PORTS)} to the internet`, `Ingress from 0.0.0.0/0 on ${named(c.data, DATA_PORTS)}${scope}; ${where}.`, fix, { keyPart: `${it.id}|data` });
      if (c.wide && !c.admin.length && !c.data.length) f('net.gcp-fw-wide-open', pub.length ? 'medium' : 'low', it, `${label} opens a wide port range to the internet`, `Ingress from 0.0.0.0/0 on ${c.text}${scope}; ${where}.`, 'Open only the ports the service listens on.', { keyPart: `${it.id}|wide` });
    }
  };
  const gfwRules = [];   // [{ it, rule, ranges, path, label }] ingress allows from the internet, for exposure too
  for (const x of gby('firewall')) {
    const d = x.data;
    if (d.disabled || d.direction !== 'INGRESS' || d.action !== 'allow' || !d.sourceRanges.some((s) => WORLD.has(s))) continue;
    gfwRules.push({ it: { ...x, cloud: 'gcp' }, rule: d, ranges: gcpPorts(d.rules), path: x.vpc, label: `Firewall rule ${x.name}` });
  }
  for (const p of gby('firewall-policy')) for (const r of p.data.rules) {
    if (r.disabled || r.direction !== 'INGRESS' || r.action !== 'allow' || !r.sourceRanges.some((s) => WORLD.has(s))) continue;
    for (const path of p.data.networks) gfwRules.push({ it: { ...p, cloud: 'gcp', vpc: path, id: `${p.id}#${r.priority}` }, rule: r, ranges: gcpPorts(r.layer4), path, label: `Firewall policy ${p.name}, rule ${r.priority}` });
  }
  for (const g of gfwRules) gfw(g.it, g.rule, g.ranges, g.path, g.label);
  for (const n of networks.values()) {
    const it = { ...n, cloud: 'gcp' };
    if (n.name === 'default' || n.data.autoSubnets) f('net.gcp-default-network', 'medium', it, n.name === 'default' ? `Project ${n.owner} still has the default network` : `Network ${n.name} creates subnets on its own`,
      `${n.data.autoSubnets ? 'An auto mode network has a subnet in every region, ' : ''}${n.name === 'default' ? 'and the default network comes with firewall rules that open SSH, RDP and ICMP to the internet.' : 'with address ranges you did not plan.'}`, 'Create a custom mode network with the subnets you need, move workloads, delete this one (CIS 3.1).');
    if (n.data.legacy) f('net.gcp-legacy-network', 'medium', it, `Network ${n.name} is a legacy network`, 'Legacy networks have one range for every region and no subnets: no flow logs, no private Google access.', 'Move to a VPC network (CIS 3.2).');
    const subs = gby('subnet').filter((s) => s.vpc === n.id && s.data.purpose === 'PRIVATE');
    const off = subs.filter((s) => !s.data.flowLogs);
    if (off.length) f('net.gcp-flow-logs-off', 'low', it, `No flow logs on ${off.length} subnet${off.length === 1 ? '' : 's'} of ${n.name}`, `${off.map((s) => `${s.name} (${s.region})`).slice(0, 5).join(', ')}: nothing records which addresses talked to what.`, 'Turn on VPC flow logs on each subnet (CIS 3.8).');
    for (const p of n.data.peerings) {
      const other = p.network?.split('/')[1];
      if (other && !ownGcp(other) && p.state === 'ACTIVE') f('net.gcp-peering-external', 'medium', it, `Network ${n.name} peers with project ${other}, which is not yours`,
        `Peering ${p.name} connects ${n.id} to ${p.network}. Routes ${p.exportCustom ? 'including your custom routes ' : ''}are shared: their side can reach your subnets, as far as your firewall rules let it.`, 'Confirm the other party, and keep firewall rules for its ranges tight.', { keyPart: `${n.id}|${p.name}` });
    }
  }
  for (const t of gby('vpn-tunnel')) if (t.data.status && t.data.status !== 'ESTABLISHED')
    f('net.gcp-vpn-down', 'low', { ...t, cloud: 'gcp' }, `VPN tunnel ${t.name} is not up`, `Status ${t.data.status}${t.data.detail ? `: ${t.data.detail}` : ''}. Peer ${t.data.peerIp}.`, 'Check the peer side, or delete the tunnel if it is no longer used.');

  for (const i of instances) {
    const ips = pubOf(i); if (!ips.length) continue;
    const open = [];
    for (const g of gfwRules) if (i.data.interfaces.some((x) => x.network === g.path) && targetsOf(g.rule, g.path).includes(i)) { if (g.ranges && !g.ranges.length) continue; open.push({ ranges: g.ranges, via: g.label.toLowerCase(), proto: g.ranges === null ? 'all' : 'tcp' }); }
    exposures.push({ cloud: 'gcp', owner: i.owner, vpc: i.vpc, region: i.region, kind: 'instance', id: i.id, name: i.name, addresses: ips,
      ports: open.map((x) => ({ proto: x.proto, ports: portText(x.ranges), via: x.via })), severity: open.length ? sevPorts(open) : 'none' });
  }
  for (const r of gby('forwarding-rule')) exposures.push({ cloud: 'gcp', owner: r.owner, vpc: r.vpc, region: r.region, kind: 'load-balancer', id: r.id, name: r.name, addresses: [r.data.ip],
    ports: [{ proto: String(r.data.proto || 'tcp').toLowerCase(), ports: r.data.ports.join(', ') || 'every port', via: `forwarding rule (${r.data.scheme})` }],
    severity: worstOf(r.data.ports.map((p) => { const [a] = String(p).split('-').map(Number); return ADMIN_PORTS[a] || DATA_PORTS[a] ? 'high' : 'low'; })) });

  // ---------------------------------------------------------------- the graph
  const graph = buildGraph({ items, vpcs, subnets, publicSubnet, tableOf, peerings, atts, tgws, cgws, networks, exposures, ownAws, awsName, ownGcp, awsAccounts, gcpProjects });
  // connected networks whose address ranges overlap: traffic between them cannot be routed as it should
  const cidrs = new Map(graph.nodes.map((n) => [n.id, n.cidrs || []]));
  for (const l of graph.links) {
    if (!['peering', 'vpn', 'tgw'].includes(l.kind)) continue;
    const a = cidrs.get(l.from) || [], b = cidrs.get(l.to) || [];
    const clash = a.flatMap((x) => b.filter((y) => overlaps(x, y)).map((y) => `${x} and ${y}`));
    if (!clash.length) continue;
    const na = graph.nodes.find((n) => n.id === l.from), nb = graph.nodes.find((n) => n.id === l.to);
    f('net.cidr-overlap', 'low', { cloud: na.cloud, owner: na.owner, type: na.kind, id: na.nativeId, name: na.label, vpc: na.nativeId }, `${na.label} and ${nb.label} use overlapping addresses`,
      `They are connected (${l.kind}) but both use ${clash.slice(0, 3).join(', ')}: traffic to the shared range stays on one side.`, 'Renumber one side, or connect them only through NAT.', { keyPart: `${l.id}` });
  }
  for (const n of graph.nodes) {
    n.findings = findings.filter((x) => (n.kind === 'vpc' || n.kind === 'network') && x.cloud === n.cloud && x.owner === n.owner && (x.vpc === n.nativeId || x.nativeId === n.nativeId)).length;
    n.worst = worstOf(findings.filter((x) => x.cloud === n.cloud && x.owner === n.owner && (x.vpc === n.nativeId || x.nativeId === n.nativeId)).map((x) => x.severity));
  }
  return { findings, exposures, graph };
}

/** Nodes and links of the map. Node ids: aws:vpc:<acct>:<vpc>, aws:tgw:<tgw>, gcp:net:<path>, peer:<ip>, internet. */
function buildGraph(x) {
  const nodes = new Map(), links = new Map();
  const node = (id, n) => { if (!nodes.has(id)) nodes.set(id, { id, ...n }); return nodes.get(id); };
  const link = (from, to, kind, l = {}) => { const [a, b] = from < to ? [from, to] : [to, from]; const id = `${kind}:${a}|${b}${l.sub ? `|${l.sub}` : ''}`; if (!links.has(id)) links.set(id, { id, from, to, kind, ...l }); return links.get(id); };
  const internet = () => node('internet', { kind: 'internet', cloud: null, label: 'Internet', owner: null });
  const exp = new Map(); for (const e of x.exposures) { const k = `${e.cloud}|${e.owner}|${e.vpc}`; if (!exp.has(k)) exp.set(k, []); exp.get(k).push(e); }
  const items = (cloud, type) => x.items.filter((i) => i.cloud === cloud && i.type === type);

  // AWS VPCs
  const vpcNode = (owner, vpc, region, stub = {}) => node(`aws:vpc:${owner}:${vpc}`, { kind: 'vpc', cloud: 'aws', owner, nativeId: vpc, region, label: stub.label || vpc, ownerName: x.awsName(owner),
    yours: x.ownAws(owner), read: x.awsAccounts.has(owner), cidrs: stub.cidrs || [], stub: true });
  for (const v of x.vpcs.values()) {
    const subs = x.subnets.filter((s) => s.owner === v.owner && s.vpc === v.id);
    const pub = subs.filter((s) => x.publicSubnet.get(`${s.owner}|${s.id}`));
    const igw = items('aws', 'igw').find((g) => g.owner === v.owner && g.data.vpcs.includes(v.id));
    const nats = items('aws', 'nat').filter((n) => n.owner === v.owner && n.vpc === v.id && n.data.public);
    const e = exp.get(`aws|${v.owner}|${v.id}`) || [];
    const n = Object.assign(vpcNode(v.owner, v.id, v.region), { label: v.name !== v.id ? v.name : v.data.isDefault ? `default VPC (${v.region})` : v.id, stub: false, cidrs: v.data.cidrs, isDefault: v.data.isDefault,
      subnets: { total: subs.length, public: pub.length }, igw: igw?.id || null, nats: nats.length, natIps: nats.flatMap((m) => m.data.publicIps),
      firewall: items('aws', 'firewall').some((f) => f.owner === v.owner && f.vpc === v.id), endpoints: items('aws', 'endpoint').filter((p) => p.owner === v.owner && p.vpc === v.id).length,
      exposed: e.filter((z) => z.ports.length).length, interfaces: items('aws', 'eni').filter((m) => m.owner === v.owner && m.vpc === v.id).length });
    if (igw || nats.length) {
      const l = link(n.id, internet().id, 'internet', { egress: igw ? (nats.length ? 'internet gateway, NAT' : 'internet gateway') : 'NAT', ingress: n.exposed, publicSubnets: pub.length });
      l.from = n.id; l.to = 'internet';
    }
  }
  // VPC peering
  for (const p of x.peerings.values()) {
    const r = p.data.requester, a = p.data.accepter; if (!r || !a) continue;
    const from = vpcNode(r.account, r.vpc, r.region, { cidrs: r.cidrs }), to = vpcNode(a.account, a.vpc, a.region, { cidrs: a.cidrs });
    const routed = x.items.some((t) => t.cloud === 'aws' && t.type === 'route-table' && t.data.routes.some((rt) => rt.target.type === 'peering' && rt.target.id === p.id));
    link(from.id, to.id, 'peering', { name: p.name, nativeId: p.id, status: p.data.status, routed, crossAccount: r.account !== a.account, outside: !x.ownAws(r.account) || !x.ownAws(a.account) });
  }
  // transit gateways and their attachments
  const tgwNode = (id, owner) => node(`aws:tgw:${id}`, { kind: 'tgw', cloud: 'aws', owner, nativeId: id, label: x.tgws.get(id)?.name || id, ownerName: x.awsName(owner), yours: x.ownAws(owner), cidrs: [] });
  const vpnHub = new Map();   // vpn id -> node id of what it hangs off (transit gateway, or the VPC of its virtual private gateway)
  for (const a of x.atts.values()) {
    const t = tgwNode(a.data.tgw, a.data.tgwOwner);
    if (a.data.resourceType === 'vpc') {
      const v = x.vpcs.get(`${a.data.resourceOwner}|${a.data.resourceId}`);
      const vn = vpcNode(a.data.resourceOwner, a.data.resourceId, v?.region || a.region, { cidrs: v?.data.cidrs });
      link(vn.id, t.id, 'tgw', { name: a.name, nativeId: a.id, status: a.data.state, crossAccount: a.data.tgwOwner !== a.data.resourceOwner, outside: !x.ownAws(a.data.tgwOwner) || !x.ownAws(a.data.resourceOwner) });
    } else if (a.data.resourceType === 'vpn') vpnHub.set(a.data.resourceId, t.id);
    else if (a.data.resourceType === 'peering') link(t.id, tgwNode(a.data.resourceId, a.data.resourceOwner).id, 'tgw-peering', { name: a.name, nativeId: a.id, status: a.data.state });
  }
  const vgws = items('aws', 'vgw');
  // Google Cloud networks (and peers of theirs that are not read)
  const netNode = (path, stub = {}) => { const p = path.split('/')[1]; return node(`gcp:net:${path}`, { kind: 'network', cloud: 'gcp', owner: p, nativeId: path, label: stub.label || path.split('/').pop(), ownerName: x.gcpProjects.get(p)?.name || null,
    yours: x.ownGcp(p), read: x.gcpProjects.has(p), cidrs: [], stub: true }); };
  const gsubs = items('gcp', 'subnet'), ginst = items('gcp', 'instance');
  for (const n of x.networks.values()) {
    const subs = gsubs.filter((s) => s.vpc === n.id), e = exp.get(`gcp|${n.owner}|${n.id}`) || [];
    const nat = items('gcp', 'router').filter((r) => r.vpc === n.id && r.data.nats.length);
    const withIp = ginst.filter((i) => i.vpc === n.id && i.data.interfaces.some((y) => y.natIps.length));
    const usedBy = [...new Set(ginst.filter((i) => i.owner !== n.owner && i.data.interfaces.some((y) => y.network === n.id)).map((i) => i.owner))];
    const nn = Object.assign(netNode(n.id), { label: n.name, stub: false, cidrs: subs.map((s) => s.data.cidr), regions: [...new Set(subs.map((s) => s.region))], subnets: { total: subs.length, public: 0 },
      auto: n.data.autoSubnets, nats: nat.length, exposed: e.filter((z) => z.ports.length).length, instances: ginst.filter((i) => i.vpc === n.id).length, externalIps: withIp.length, sharedWith: usedBy });
    const route = items('gcp', 'route').some((r) => r.vpc === n.id && r.data.nextHop.type === 'internet');
    if (route || nat.length || withIp.length || e.length) link(nn.id, internet().id, 'internet', { egress: [route ? 'default internet route' : null, nat.length ? 'Cloud NAT' : null].filter(Boolean).join(', ') || 'external addresses', ingress: nn.exposed });
    for (const p of n.data.peerings) if (p.network) link(nn.id, netNode(p.network).id, 'peering', { name: p.name, status: p.state, crossProject: p.network.split('/')[1] !== n.owner, outside: !x.ownGcp(p.network.split('/')[1]) });
  }
  for (const n of x.networks.values()) for (const p of n.data.peerings) { const o = nodes.get(`gcp:net:${p.network}`); if (o?.stub) o.label = p.network.split('/').pop(); }

  // VPNs: AWS side (tunnel outside addresses, customer gateway address) matched with Google Cloud's (HA VPN interface
  // addresses, tunnel peer addresses). One link per pair of ends, with every tunnel listed.
  const gGw = items('gcp', 'vpn-gateway'), gTun = items('gcp', 'vpn-tunnel');
  const gwByIp = new Map(); for (const g of gGw) for (const ip of g.data.ips) gwByIp.set(ip, g);
  const tunByPeer = new Map(); for (const t of gTun) if (t.data.peerIp) tunByPeer.set(t.data.peerIp, t);
  const gwById = new Map(gGw.map((g) => [g.id, g]));
  const matchedTunnels = new Set();
  for (const v of items('aws', 'vpn')) {
    const cgw = x.cgws.get(`${v.owner}|${v.data.cgw}`);
    let hub = vpnHub.get(v.id) || (v.data.tgw ? tgwNode(v.data.tgw, v.owner).id : null);
    if (!hub && v.data.vgw) { const g = vgws.find((y) => y.owner === v.owner && y.id === v.data.vgw); if (g?.data.vpcs[0]) hub = vpcNode(v.owner, g.data.vpcs[0], v.region).id; }
    if (!hub) continue;
    const outs = v.data.tunnels.map((t) => t.outsideIp);
    const gw = (cgw && gwByIp.get(cgw.data.ip)) || outs.map((ip) => tunByPeer.get(ip)).filter(Boolean).map((t) => gwById.get(t.data.gateway)).find(Boolean) || null;
    const tunnels = v.data.tunnels.map((t) => { const g = tunByPeer.get(t.outsideIp); if (g) matchedTunnels.add(g.id); return { aws: t.outsideIp, awsStatus: t.status, gcp: g?.name || null, gcpStatus: g?.data.status || null }; });
    if (gw && gw.vpc) {
      const l = link(hub, netNode(gw.vpc).id, 'vpn', { sub: '', cross: true, name: 'site-to-site VPN', tunnels: [], vpns: [], gateway: gw.name, gatewayIps: gw.data.ips });
      l.tunnels.push(...tunnels); l.vpns.push({ id: v.id, name: v.name, cgw: cgw?.data.ip || null, state: v.data.state });
      l.up = l.tunnels.filter((t) => t.awsStatus === 'UP' && (!t.gcpStatus || t.gcpStatus === 'ESTABLISHED')).length;
    } else {
      const peer = node(`peer:${cgw?.data.ip || v.data.cgw}`, { kind: 'peer', cloud: null, owner: null, label: cgw?.name || cgw?.data.ip || v.data.cgw, ip: cgw?.data.ip || null, cidrs: [] });
      const l = link(hub, peer.id, 'vpn', { sub: v.id, name: v.name, tunnels, vpns: [{ id: v.id, name: v.name, cgw: cgw?.data.ip || null, state: v.data.state }] });
      l.up = tunnels.filter((t) => t.awsStatus === 'UP').length;
    }
  }
  // Google Cloud tunnels no AWS VPN matched: to another Google gateway, or to a peer (on-premises, another cloud)
  for (const t of gTun.filter((y) => !matchedTunnels.has(y.id))) {
    const gw = gwById.get(t.data.gateway); if (!gw?.vpc) continue;
    const other = t.data.peerGateway && gwById.get(t.data.peerGateway);
    const to = other?.vpc ? netNode(other.vpc).id : node(`peer:${t.data.peerIp}`, { kind: 'peer', cloud: null, owner: null, label: t.data.peerIp, ip: t.data.peerIp, cidrs: [] }).id;
    const l = link(netNode(gw.vpc).id, to, 'vpn', { sub: other ? '' : t.data.peerIp, name: 'Cloud VPN', tunnels: [], vpns: [] });
    l.tunnels.push({ gcp: t.name, gcpStatus: t.data.status, peer: t.data.peerIp });
    l.up = l.tunnels.filter((y) => y.gcpStatus === 'ESTABLISHED').length;
  }
  for (const a of items('gcp', 'interconnect')) {
    const r = items('gcp', 'router').find((y) => y.owner === a.owner && y.name === a.data.router); if (!r?.vpc) continue;
    const ic = node(`ic:${a.data.interconnect || a.data.partner || a.name}`, { kind: 'peer', cloud: null, owner: null, label: a.data.partner ? `${a.data.partner} (Partner Interconnect)` : `Interconnect ${a.data.interconnect || a.name}`, cidrs: [] });
    link(netNode(r.vpc).id, ic.id, 'interconnect', { name: a.name, status: a.data.state });
  }
  return { nodes: [...nodes.values()], links: [...links.values()] };
}
