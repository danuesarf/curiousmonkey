// The network analyzer: from what the reader stored (src/network/awsReader.js, gcpReader.js) to
//   - findings: admin, database or every port open to the internet (security groups, firewall rules, network
//     firewall policies), default networks and VPCs, missing flow logs, public subnets that hand out public IPs, network
//     ACLs that let the internet in, peering and transit gateway attachments with accounts or projects that are not
//     yours, VPN tunnels down, overlapping address ranges between networks that are connected;
//   - exposure: what the internet can reach, address by address and port by port;
//   - the graph: VPCs and networks, transit gateways, the internet and VPN peers as nodes; peering, transit gateway
//     attachments, VPNs (AWS to Google Cloud matched by their tunnel addresses), Interconnect and the internet as links.
//     A VPC a network account shares with member accounts (AWS RAM) is one node under its owner, with each member's
//     part of it (a "slice") in the member's account and a share line between them.
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

// ---------------------------------------------------------------- shared VPCs (AWS RAM, Google Cloud Shared VPC)
const ACCOUNT = /^\d{12}$/;
// a Google Cloud network's project, from its path (projects/<project>/global/networks/<name>)
const projectOf = (path) => (/^projects\//.test(path || '') ? path.split('/')[1] : null);
/**
 * One VPC per real owner. A VPC a network account shares with member accounts (AWS RAM) is read several ways: the
 * owner reads it with its subnets, routes and gateways, and the network interfaces members run in it; each member reads
 * the VPC and its subnets (with the owner's ID) and its own interfaces and security groups. Here they become one:
 *   - the VPC and each subnet once, under the owner: the owner's own read, else a member's view (ownerNotRead);
 *   - each network interface once, under the account it belongs to (the member's own read when there is one);
 *   - `vpcOwner` on every AWS item that sits in a VPC: the account that owns the VPC (in a shared VPC, not the
 *     account the item belongs to).
 * Google Cloud's Shared VPC is simpler to read: a service project's instances, load balancers and endpoints name the
 * host's network in their own path, and the host lists its service projects (xpn). Its items get `vpcOwner` too (the
 * network's project), and each service project becomes a member of the host network it runs in, or, when it runs
 * nothing there yet, of the host it is attached to (`attached`: the host's networks, as it may use any it is given).
 * Returns { items, shares: Map('<cloud>|<owner>|<vpc>' -> { cloud, owner, vpc, members: Map(account or project ->
 * { via: Set('read' | 'interfaces' | 'ram' | 'instances' | 'xpn'), share, shareName }), principals: [OU or
 * organization ARNs] }), vpcOwnerOf(owner, vpc) }.
 */
export function shareAware(items) {
  const realVpc = new Map(), ownRead = new Set();
  for (const i of items) if (i.cloud === 'aws') {
    if (i.type === 'vpc') realVpc.set(`${i.owner}|${i.id}`, i.data?.owner || i.owner);
    if (['vpc', 'subnet', 'eni'].includes(i.type) && (!i.data?.owner || i.data.owner === i.owner)) ownRead.add(`${i.type}|${i.owner}|${i.id}`);
  }
  const vpcOwnerOf = (owner, vpc) => (!vpc ? owner : projectOf(vpc) || realVpc.get(`${owner}|${vpc}`) || owner);
  const shares = new Map();
  const share = (owner, vpc, cloud = 'aws') => { const k = `${cloud}|${owner}|${vpc}`; if (!shares.has(k)) shares.set(k, { cloud, owner, vpc, members: new Map(), principals: [] }); return shares.get(k); };
  const member = (sh, acct, via, extra = {}) => { if (acct === sh.owner) return; if (!sh.members.has(acct)) sh.members.set(acct, { via: new Set() }); const m = sh.members.get(acct); m.via.add(via); Object.assign(m, extra); };
  const out = [], kept = new Set();
  for (const i of items) {
    if (i.cloud === 'gcp') {
      // a service project's instance, load balancer or endpoint in the host's network
      const host = projectOf(i.vpc);
      if (host && host !== i.owner && ['instance', 'forwarding-rule', 'psc-endpoint', 'ilb'].includes(i.type)) member(share(host, i.vpc, 'gcp'), i.owner, 'instances');
      out.push(host ? { ...i, vpcOwner: host } : i);
      continue;
    }
    if (i.cloud !== 'aws') { out.push(i); continue; }
    const real = i.data?.owner;
    if ((i.type === 'vpc' || i.type === 'subnet') && real && ACCOUNT.test(real) && real !== i.owner) {
      // a member's view of what the owner shares with it
      member(share(real, i.type === 'vpc' ? i.id : i.vpc), i.owner, 'read');
      const k = `${i.type}|${real}|${i.id}`;
      if (ownRead.has(k) || kept.has(k)) continue;
      kept.add(k);
      out.push({ ...i, owner: real, account_id: null, vpcOwner: real, data: { ...i.data, ownerNotRead: true } });
      continue;
    }
    if (i.type === 'eni' && real && ACCOUNT.test(real) && real !== i.owner && i.data.kind !== 'transit_gateway' && vpcOwnerOf(i.owner, i.vpc) === i.owner) {
      // the owner's view of an interface a member runs in its subnets
      member(share(i.owner, i.vpc), real, 'interfaces');
      const k = `eni|${real}|${i.id}`;
      if (ownRead.has(k) || kept.has(k)) continue;
      kept.add(k);
      out.push({ ...i, owner: real, account_id: null, vpcOwner: i.owner, data: { ...i.data, seenBy: i.owner } });
      continue;
    }
    out.push(i.vpc ? { ...i, vpcOwner: vpcOwnerOf(i.owner, i.vpc) } : i);
  }
  // who the owner shares its subnets with (RAM), including accounts that are not connected, OUs and the organization
  const subnetVpc = new Map(items.filter((i) => i.cloud === 'aws' && i.type === 'subnet').map((i) => [`${i.data?.owner || i.owner}|${i.id}`, i.vpc]));
  for (const r of items.filter((i) => i.cloud === 'aws' && i.type === 'ram-share')) {
    const vpcSet = new Set(r.data.subnets.map((x) => subnetVpc.get(`${r.owner}|${x}`)).filter(Boolean));
    for (const vpc of vpcSet) {
      const sh = share(r.owner, vpc);
      for (const p of r.data.principals) {
        if (ACCOUNT.test(p.id)) member(sh, p.id, 'ram', { share: r.id, shareName: r.name, external: p.external || r.data.allowExternal });
        else if (!sh.principals.includes(p.id)) sh.principals.push(p.id);
      }
    }
  }
  // service projects attached to a Shared VPC host (xpn): members of each of its networks, as attached
  const gnets = items.filter((i) => i.cloud === 'gcp' && i.type === 'network');
  for (const x of items.filter((i) => i.cloud === 'gcp' && i.type === 'shared-vpc')) {
    for (const n of gnets.filter((y) => y.owner === x.data.host)) for (const svc of x.data.services) member(share(x.data.host, n.id, 'gcp'), svc, 'xpn');
  }
  for (const [k, sh] of shares) if (!sh.members.size && !sh.principals.length) shares.delete(k);
  return { items: out, shares, vpcOwnerOf };
}

/**
 * Everything the analyzer needs to know about the estate:
 *   awsAccounts: Map(12-digit -> { id, name }) connected; orgAccounts: Map(12-digit -> name); vendor(acct) -> name|null
 *   gcpProjects: Map(projectId -> { name }) read; ownProject(projectId) -> true when it is yours but not read
 */
export function analyzeNetwork(rawItems, estate = {}, policy = DEFAULT_POLICY, usage = null) {
  const { items, shares, vpcOwnerOf } = shareAware(rawItems);
  const awsAccounts = estate.awsAccounts || new Map(), orgAccounts = estate.orgAccounts || new Map(), gcpProjects = estate.gcpProjects || new Map();
  const ownAws = (a) => awsAccounts.has(a) || orgAccounts.has(a);
  const awsName = (a) => awsAccounts.get(a)?.name || orgAccounts.get(a) || estate.vendor?.(a) || null;
  const ownGcp = (p) => gcpProjects.has(p) || !!estate.ownProject?.(p);
  const findings = [], exposures = [];
  const f = (control, builtIn, it, title, detail, suggestion, extra = {}) => {
    const severity = severityOf(policy, control, builtIn); if (!severity) return;
    findings.push({ key: `${control}|${it.cloud}|${it.owner}|${extra.keyPart || it.id}`.slice(0, 500), control, severity, cloud: it.cloud, owner: it.owner, itemType: it.type, nativeId: it.id,
      itemName: it.name, vpc: it.vpc, vpcOwner: it.vpcOwner || it.owner, region: it.region || null, title, detail, suggestion });
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
  const enisIn = new Map(); for (const n of enis) { const k = key(n.vpcOwner || n.owner, n.vpc); enisIn.set(k, (enisIn.get(k) || 0) + 1); }
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

  // Direct Connect: virtual interfaces down, BGP down, and gateways that hang on one connection
  for (const v of by('dx-vif')) {
    const down = v.data.bgp.filter((b) => b.status !== 'up');
    if (!['available', 'down'].includes(v.data.state) && v.data.state) continue;     // being created or deleted
    if (v.data.state === 'down' || (down.length && down.length === v.data.bgp.length)) f('net.dx-down', 'medium', { ...v, cloud: 'aws' }, `Direct Connect virtual interface ${v.name} is down`,
      `${v.data.kind} interface on ${v.data.connection} (VLAN ${v.data.vlan}): ${v.data.state === 'down' ? 'the interface is down' : 'no BGP session is up'}. Whatever routes over it has fallen back, or stopped.`, 'Check the connection and the router on your side; or delete the interface if it is no longer used.');
    else if (down.length) f('net.dx-down', 'low', { ...v, cloud: 'aws' }, `Direct Connect virtual interface ${v.name} has a BGP session down`, `${down.length} of ${v.data.bgp.length} BGP sessions are down.`, 'Bring the session up.');
  }
  const dxBehind = new Map();   // dx gateway or virtual private gateway -> connections that reach it
  for (const v of by('dx-vif')) { const k = v.data.dxgw || v.data.vgw; if (!k) continue; if (!dxBehind.has(k)) dxBehind.set(k, { conns: new Set(), item: v }); dxBehind.get(k).conns.add(v.data.connection); }
  for (const [k, x] of dxBehind) if (x.conns.size === 1) f('net.dx-single', 'low', { ...x.item, cloud: 'aws', id: k, type: k.startsWith('vgw-') ? 'vgw' : 'dx-gateway', name: by('dx-gateway').find((g) => g.id === k)?.name || k },
    `${k.startsWith('vgw-') ? 'Virtual private gateway' : 'Direct Connect gateway'} ${k} hangs on one Direct Connect connection`, `Every virtual interface to it uses ${[...x.conns][0]}: a fault on that line, or maintenance at its location, cuts it off.`,
    'Add a second connection at another location (AWS resiliency recommendations), or a VPN as a backup.', { keyPart: k });
  // transit gateway routes that go nowhere
  for (const t of by('tgw-route-table')) {
    const bh = t.data.routes.filter((r) => r.state === 'blackhole');
    if (bh.length) f('net.tgw-blackhole', 'low', { ...t, cloud: 'aws' }, `Transit gateway route table ${t.name} has blackhole routes`, `${bh.map((r) => r.dest).slice(0, 5).join(', ')}: traffic to them is dropped, often because the attachment behind them was deleted.`, 'Delete the routes, or attach what they pointed to again.');
  }
  // Client VPN: who may reach what, and whether connections are logged
  for (const c of by('client-vpn')) {
    const it = { ...c, cloud: 'aws' }, v = vpcs.get(key(c.vpcOwner || c.owner, c.vpc));
    const wide = c.data.rules.filter((r) => r.everyone && (r.cidr === '0.0.0.0/0' || (v && v.data.cidrs.includes(r.cidr))));
    if (wide.length) f('net.client-vpn-wide', 'low', it, `Client VPN ${c.name} lets every user reach ${wide.map((r) => r.cidr).join(', ')}`, 'An authorization rule for all users covers the whole VPC (or everything): anyone who can connect reaches every subnet.', 'Authorize groups to the subnets they need.');
    if (!c.data.connectionLog) f('net.client-vpn-no-log', 'low', it, `Client VPN ${c.name} does not log connections`, 'Without connection logging nobody can say who was connected when.', 'Turn on connection logging to CloudWatch Logs.');
  }
  // PrivateLink services consumed by accounts that are not yours
  for (const v of by('endpoint-service')) for (const c of v.data.connections.filter((y) => y.state === 'available' && y.account && !ownAws(y.account)))
    f('net.privatelink-external', 'medium', { ...v, cloud: 'aws' }, `PrivateLink service ${v.name.split('.').pop()} is used by ${awsName(c.account) || `account ${c.account}`}`,
      `Endpoint ${c.endpoint} in account ${c.account} connects to it${v.data.acceptance ? '' : ', and connections are accepted without approval'}. It reaches whatever the load balancer behind the service serves.`, 'Confirm the consumer; require acceptance and allow only the principals that need it.', { keyPart: `${v.id}|${c.account}` });

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
    exposures.push({ cloud: 'aws', owner: n.owner, vpc: n.vpc, vpcOwner: n.vpcOwner || n.owner, region: n.region, kind: 'interface', id: n.id, name: n.data.instance ? `${n.name !== n.id ? n.name : 'instance'} (${n.data.instance})` : n.name,
      addresses: ips, ports: open.map((x) => ({ proto: x.proto, ports: portText(x.ranges), via: `security group ${x.via}` })), severity: open.length ? sevPorts(open) : 'none' });
  }
  for (const b of lbs.filter((x) => x.data.scheme === 'internet-facing')) {
    const open = b.data.groups.length ? worldPorts(b.owner, b.data.groups) : null;
    const ls = b.data.listeners.filter((l) => !open || open.some((x) => covers(x.ranges, l.port)));
    exposures.push({ cloud: 'aws', owner: b.owner, vpc: b.vpc, vpcOwner: b.vpcOwner || b.owner, region: b.region, kind: 'load-balancer', id: b.id, name: b.name, addresses: [b.data.dns],
      ports: ls.map((l) => ({ proto: /UDP/i.test(l.proto) && !/TCP_UDP/i.test(l.proto) ? 'udp' : 'tcp', ports: String(l.port), via: `${l.proto} listener${b.data.groups.length ? '' : ' (no security group)'}` })),
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

  for (const a of gby('service-attachment')) for (const e of a.data.connected.filter((y) => y.status === 'ACCEPTED')) {
    const p = e.network?.split('/')[1] || e.endpoint?.split('/')[1];
    if (p && !ownGcp(p)) f('net.gcp-psc-external', 'medium', { ...a, cloud: 'gcp' }, `Private Service Connect service ${a.name} is used from project ${p}, which is not yours`,
      `Endpoint ${e.endpoint} connects to it${a.data.preference === 'ACCEPT_AUTOMATIC' ? ', and any project may connect without approval' : ''}. It reaches what the load balancer behind it serves.`, 'Accept only the projects that need it (ACCEPT_MANUAL with an accept list).', { keyPart: `${a.id}|${p}` });
  }
  for (const i of instances) {
    const ips = pubOf(i); if (!ips.length) continue;
    const open = [];
    for (const g of gfwRules) if (i.data.interfaces.some((x) => x.network === g.path) && targetsOf(g.rule, g.path).includes(i)) { if (g.ranges && !g.ranges.length) continue; open.push({ ranges: g.ranges, via: g.label.toLowerCase(), proto: g.ranges === null ? 'all' : 'tcp' }); }
    exposures.push({ cloud: 'gcp', owner: i.owner, vpc: i.vpc, vpcOwner: i.vpcOwner || i.owner, region: i.region, kind: 'instance', id: i.id, name: i.name, addresses: ips,
      ports: open.map((x) => ({ proto: x.proto, ports: portText(x.ranges), via: x.via })), severity: open.length ? sevPorts(open) : 'none' });
  }
  for (const r of gby('forwarding-rule')) exposures.push({ cloud: 'gcp', owner: r.owner, vpc: r.vpc, vpcOwner: r.vpcOwner || r.owner, region: r.region, kind: 'load-balancer', id: r.id, name: r.name, addresses: [r.data.ip],
    ports: [{ proto: String(r.data.proto || 'tcp').toLowerCase(), ports: r.data.ports.join(', ') || 'every port', via: `forwarding rule (${r.data.scheme})` }],
    severity: worstOf(r.data.ports.map((p) => { const [a] = String(p).split('-').map(Number); return ADMIN_PORTS[a] || DATA_PORTS[a] ? 'high' : 'low'; })) });

  // ---------------------------------------------------------------- the graph
  // subnets shared (AWS RAM) with an account that is neither connected nor in the organization
  for (const sh of shares.values()) for (const [acct, m] of sh.members) {
    if (sh.cloud !== 'aws' || !m.via.has('ram') || ownAws(acct)) continue;
    const v = vpcs.get(key(sh.owner, sh.vpc)); if (!v) continue;
    f('net.vpc-shared-external', 'medium', { ...v, cloud: 'aws', type: 'ram-share', id: m.share || v.id, name: m.shareName || v.name }, `VPC ${v.name} is shared with ${awsName(acct) || `account ${acct}`}, outside your estate`,
      `Subnets of ${v.name} are shared through AWS RAM${m.shareName ? ` (${m.shareName})` : ''} with account ${acct}, which is neither connected here nor in your organization. It can run resources inside the VPC, behind its routes and next to what runs there.`,
      'Share only with accounts in your organization, and turn off sharing with external principals in RAM.', { keyPart: `${sh.vpc}|${acct}` });
  }

  const graph = buildGraph({ items, vpcs, subnets, publicSubnet, tableOf, peerings, atts, tgws, cgws, networks, exposures, ownAws, awsName, ownGcp, awsAccounts, gcpProjects, shares });
  if (usage) applyUsage(graph, exposures, usage, f, estate.now || Date.now());
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
  // a VPC counts what is open in it whoever runs it; a member's slice counts its own part
  const about = (n) => findings.filter((x) => x.cloud === n.cloud && (n.kind === 'slice' ? x.owner === n.owner && x.vpc === n.nativeId && x.vpcOwner === n.vpcOwner
    : (x.vpcOwner === n.owner && x.vpc === n.nativeId) || (x.owner === n.owner && x.nativeId === n.nativeId)));
  for (const n of graph.nodes) {
    const mine = about(n);
    n.findings = ['vpc', 'network', 'slice'].includes(n.kind) ? mine.length : 0;
    n.worst = worstOf(mine.map((x) => x.severity));
  }
  return { findings, exposures, graph, vpcOwnerOf, items, shares };
}

// ---------------------------------------------------------------- what the flow logs say
const QUIET_DAYS = 3;
export const portsIn = (text) => (text === 'every port' ? null : String(text).split(',').map((x) => x.trim()).filter(Boolean).map((x) => { const [a, b] = x.split('-').map(Number); return [a, Number.isFinite(b) ? b : a]; }));
/**
 * Used, not used or not known, for every line: flow logs read for one of its VPCs (or a VPC behind its transit
 * gateway) for at least 3 days with no accepted traffic is "not used"; read for less is "quiet so far". Lines only
 * Google Cloud can see stay "not known" (Google Cloud flow logs are not read). Each public port gets what reached it.
 */
function applyUsage(graph, exposures, usage, f, now) {
  const days = (node) => { const c = usage.coverage.get(node); if (!c || new Date(c.until).getTime() < now - 6 * 36e5) return 0; return (new Date(c.until) - new Date(c.since)) / 864e5; };
  const behind = new Map();   // transit gateway or Direct Connect gateway -> VPCs it carries
  const add = (k, v) => { if (!behind.has(k)) behind.set(k, new Set()); behind.get(k).add(v); };
  for (const l of graph.links) if (l.kind === 'tgw') { const [v, t] = l.from.startsWith('aws:vpc:') ? [l.from, l.to] : [l.to, l.from]; add(t, v); }
  for (const l of graph.links) if (l.kind === 'dx') { const g = [l.from, l.to].find((x) => x.startsWith('aws:dxgw:')), t = [l.from, l.to].find((x) => x.startsWith('aws:tgw:'));
    if (g && t) for (const v of behind.get(t) || []) add(g, v); const v = [l.from, l.to].find((x) => x.startsWith('aws:vpc:')); if (g && v) add(g, v); }
  const cov = (id) => (id.startsWith('aws:vpc:') ? days(id) : Math.max(0, ...[...(behind.get(id) || [])].map(days)));
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  for (const n of graph.nodes) if (n.kind === 'vpc' && !n.stub) n.flowDays = Math.round(days(n.id) * 10) / 10;
  for (const l of graph.links) {
    // PrivateLink traffic reaches the provider through its load balancer: only the consumer's flow logs can tell
    const u = usage.links.get(l.id), covered = l.kind === 'privatelink' ? cov(l.from) : Math.max(cov(l.from), cov(l.to));
    const state = u?.bytes > 0 ? 'used' : covered >= QUIET_DAYS ? 'unused' : covered > 0 ? 'quiet' : 'unknown';
    l.usage = { state, bytes: u?.bytes || 0, flows: u?.flows || 0, rejected: u?.rejected || 0, last: u?.last || null, ports: u?.ports || [], hourly: u?.hourly || null, coveredDays: Math.round(covered * 10) / 10 };
    if (state === 'unused' && ['peering', 'tgw', 'tgw-peering', 'vpn', 'dx', 'privatelink', 'client-vpn'].includes(l.kind)) {
      const end = [l.from, l.to].map((id) => nodes.get(id)).find((n) => n?.kind === 'vpc' && !n.stub) || nodes.get(l.from);
      const other = nodes.get(end.id === l.from ? l.to : l.from);
      const what = { peering: 'VPC peering', tgw: 'Transit gateway attachment', 'tgw-peering': 'Transit gateway peering', vpn: 'VPN', dx: 'Direct Connect', privatelink: 'PrivateLink connection', 'client-vpn': 'Client VPN' }[l.kind];
      f('net.link-unused', 'low', { cloud: 'aws', owner: end.owner, type: l.kind, id: l.nativeId || l.id, name: l.name || `${end.label} ↔ ${other?.label}`, vpc: end.kind === 'vpc' ? end.nativeId : null },
        `${what} ${end.label} ↔ ${other?.label || '?'} carried nothing in ${Math.floor(covered)} days`, `The VPC flow logs read for ${Math.floor(covered)} days show no accepted traffic on it${l.usage.rejected ? ` (${l.usage.rejected} rejected)` : ''}.`,
        'Remove it if nothing needs it: an unused path is still a way in, and costs money.', { keyPart: l.id });
    }
  }
  for (const e of exposures) {
    const hits = usage.exposure.get(e.id) || new Map();
    const covered = e.cloud === 'aws' ? days(`aws:vpc:${e.vpcOwner || e.owner}:${e.vpc}`) : 0;
    e.flowDays = Math.round(covered * 10) / 10;
    for (const p of e.ports) {
      const r = portsIn(p.ports); let accepted = 0, rejected = 0, sources = 0;
      for (const [k, v] of hits) { const [proto, port] = k.split('|'); if ((p.proto === 'all' || proto === p.proto) && (r === null || r.some(([a, b]) => +port >= a && +port <= b))) { accepted += v.accepted; rejected += v.rejected; sources = Math.max(sources, v.sources); } }
      p.seen = covered > 0 ? { accepted, rejected, sources } : null;
      if (covered >= QUIET_DAYS && !accepted) f('net.open-port-unused', 'low', { cloud: e.cloud, owner: e.owner, type: e.kind, id: e.id, name: e.name, vpc: e.vpc, vpcOwner: e.vpcOwner },
        `${p.proto} ${p.ports} on ${e.name} is open to the internet but nobody used it`, `No accepted connection in ${Math.floor(covered)} days of VPC flow logs${rejected ? ` (${rejected} refused)` : ''}, through ${p.via}.`, 'Close it.', { keyPart: `${e.id}|${p.proto}|${p.ports}` });
    }
    // the busiest ports the internet reached (port 0: the rest, folded together as they were read)
    e.reached = [...hits].filter(([k, v]) => v.accepted && k.split('|')[1] !== '0').map(([k, v]) => ({ proto: k.split('|')[0], port: Number(k.split('|')[1]), ...v })).sort((a, b) => b.accepted - a.accepted).slice(0, 10);
  }
}

/** Nodes and links of the map. Node ids: aws:vpc:<acct>:<vpc>, aws:tgw:<tgw>, gcp:net:<path>, peer:<ip>, internet. */
function buildGraph(x) {
  const nodes = new Map(), links = new Map();
  const node = (id, n) => { if (!nodes.has(id)) nodes.set(id, { id, ...n }); return nodes.get(id); };
  const link = (from, to, kind, l = {}) => { const [a, b] = from < to ? [from, to] : [to, from]; const id = `${kind}:${a}|${b}${l.sub ? `|${l.sub}` : ''}`; if (!links.has(id)) links.set(id, { id, from, to, kind, ...l }); return links.get(id); };
  const internet = () => node('internet', { kind: 'internet', cloud: null, label: 'Internet', owner: null });
  const exp = new Map(); for (const e of x.exposures) { const k = `${e.cloud}|${e.vpcOwner || e.owner}|${e.vpc}`; if (!exp.has(k)) exp.set(k, []); exp.get(k).push(e); }
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
      firewall: items('aws', 'firewall').some((f) => f.owner === v.owner && f.vpc === v.id), endpoints: items('aws', 'endpoint').filter((p) => (p.vpcOwner || p.owner) === v.owner && p.vpc === v.id).length,
      exposed: e.filter((z) => z.ports.length).length, interfaces: items('aws', 'eni').filter((m) => (m.vpcOwner || m.owner) === v.owner && m.vpc === v.id).length,
      ownerNotRead: !!v.data.ownerNotRead });
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
  // Direct Connect: a connection (a line, at a location) carries virtual interfaces; a private one ends on a virtual
  // private gateway (its VPC), a transit or private one can end on a Direct Connect gateway, which is associated with
  // virtual private gateways or transit gateways, in this account or others.
  const dxConn = new Map(items('aws', 'dx-connection').map((c) => [c.id, c]));
  const dxgws = new Map(items('aws', 'dx-gateway').map((g) => [g.id, g]));
  const dxgwNode = (id, owner) => node(`aws:dxgw:${id}`, { kind: 'dxgw', cloud: 'aws', owner, nativeId: id, label: dxgws.get(id)?.name || id, ownerName: x.awsName(owner), yours: x.ownAws(owner), cidrs: [] });
  const dxNode = (connId, owner) => { const c = dxConn.get(connId); return node(`dx:${connId}`, { kind: 'peer', sub: 'dx', cloud: null, owner: null, nativeId: connId,
    label: c ? `${c.name} · ${c.data.location}` : `Direct Connect ${connId}`, bandwidth: c?.data.bandwidth || null, partner: c?.data.partner || null, state: c?.data.state || null, account: owner, cidrs: [] }); };
  const vpcOfVgw = (owner, vgwId) => { const g = vgws.find((y) => y.id === vgwId && (!owner || y.owner === owner)); return g?.data.vpcs[0] ? vpcNode(g.owner, g.data.vpcs[0], g.region).id : null; };
  for (const v of items('aws', 'dx-vif')) {
    const to = v.data.dxgw ? dxgwNode(v.data.dxgw, dxgws.get(v.data.dxgw)?.data.owner || v.owner).id : v.data.vgw ? vpcOfVgw(v.owner, v.data.vgw) : null;
    if (!to) continue;
    const up = v.data.bgp.filter((b) => b.status === 'up').length;
    const l = link(dxNode(v.data.connection, v.owner).id, to, 'dx', { sub: v.id, name: v.name, nativeId: v.id, vif: v.data.kind, vlan: v.data.vlan, status: v.data.state, prefixes: v.data.prefixes });
    l.up = up; l.total = v.data.bgp.length;
  }
  for (const a of items('aws', 'dx-association')) {
    if (a.data.state && !/^associat/.test(a.data.state)) continue;
    const gwOwner = a.data.gatewayOwner || a.owner;
    const to = a.data.gatewayType === 'transitGateway' ? tgwNode(a.data.gateway, gwOwner).id
      : vpcOfVgw(a.data.gatewayOwner, a.data.gateway) || node(`aws:vgw:${a.data.gateway}`, { kind: 'vpc', cloud: 'aws', owner: gwOwner, nativeId: a.data.gateway, label: a.data.gateway, ownerName: x.awsName(gwOwner), yours: x.ownAws(gwOwner), read: false, stub: true, cidrs: [] }).id;
    link(dxgwNode(a.data.dxgw, a.data.dxgwOwner || a.owner).id, to, 'dx', { sub: a.id, name: 'Direct Connect gateway association', nativeId: a.id, status: a.data.state, prefixes: a.data.prefixes,
      crossAccount: !!a.data.dxgwOwner && a.data.dxgwOwner !== gwOwner, outside: !x.ownAws(gwOwner) || (a.data.dxgwOwner && !x.ownAws(a.data.dxgwOwner)) });
  }
  // Client VPN: people into a VPC
  for (const c of items('aws', 'client-vpn')) {
    const v = x.vpcs.get(`${c.vpcOwner || c.owner}|${c.vpc}`); if (!v) continue;
    const users = node(`cvpn:${c.id}`, { kind: 'peer', sub: 'client-vpn', cloud: null, owner: null, nativeId: c.id, label: `Client VPN users · ${c.name}`, ip: c.data.cidr, cidrs: [c.data.cidr] });
    link(users.id, vpcNode(v.owner, v.id, v.region).id, 'client-vpn', { name: c.name, nativeId: c.id, status: c.data.status, rules: c.data.rules });
  }
  // PrivateLink: the provider's VPC (behind its load balancer) and each consumer
  const lbs = items('aws', 'lb'), eps = items('aws', 'endpoint');
  for (const sv of items('aws', 'endpoint-service')) {
    const lb = lbs.find((b) => sv.data.nlbs.includes(b.id) || sv.data.glbs.includes(b.id)); if (!lb?.vpc) continue;
    const prov = vpcNode(lb.vpcOwner || lb.owner, lb.vpc, lb.region).id;
    for (const c of sv.data.connections.filter((y) => y.state === 'available' || y.state === 'pendingAcceptance')) {
      const ep = eps.find((e) => e.id === c.endpoint);
      const cons = ep ? vpcNode(ep.vpcOwner || ep.owner, ep.vpc, ep.region).id : node(`aws:account:${c.account}`, { kind: 'peer', sub: 'account', cloud: 'aws', owner: c.account, nativeId: c.account,
        label: x.awsName(c.account) ? `${x.awsName(c.account)} (${c.account})` : `Account ${c.account}`, yours: x.ownAws(c.account), read: false, stub: true, cidrs: [] }).id;
      link(cons, prov, 'privatelink', { sub: c.endpoint, name: sv.name.split('.').pop(), nativeId: sv.id, status: c.state, endpoint: c.endpoint, outside: !x.ownAws(c.account), crossAccount: c.account !== sv.owner });
    }
  }
  // Network Connectivity Center: networks (and VPN or Interconnect spokes) on a hub
  const hubNode = (path) => node(`gcp:ncc:${path}`, { kind: 'hub', cloud: 'gcp', owner: path.split('/')[1], nativeId: path, label: path.split('/').pop(), ownerName: x.gcpProjects.get(path.split('/')[1])?.name || null, yours: x.ownGcp(path.split('/')[1]), cidrs: [] });
  const tunnelNet = new Map(gTun.map((t) => [t.id, gwById.get(t.data.gateway)?.vpc || null]));
  for (const sp of items('gcp', 'ncc-spoke')) {
    if (!sp.data.hub) continue;
    const hub = hubNode(sp.data.hub).id;
    const nets = sp.data.kind === 'vpc' ? [sp.vpc] : sp.data.uris.map((u) => tunnelNet.get(u)).filter(Boolean);
    for (const n of [...new Set(nets)].filter(Boolean)) link(netNode(n).id, hub, 'ncc', { sub: sp.id, name: sp.name, nativeId: sp.id, status: sp.data.state, spoke: sp.data.kind, crossProject: projectOf(n) !== projectOf(sp.data.hub) });
  }
  // Private Service Connect: consumer network to the producer network behind the service attachment
  const atts = new Map(items('gcp', 'service-attachment').map((a) => [a.id, a]));
  const ilbs = new Map(items('gcp', 'ilb').map((r) => [r.id, r]));
  for (const e of items('gcp', 'psc-endpoint')) {
    if (!e.vpc || !/serviceAttachments\//.test(e.data.target || '')) continue;
    const a = atts.get(e.data.target), prod = a && ilbs.get(a.data.producer)?.vpc;
    const to = prod ? netNode(prod).id : node(`gcp:psc:${e.data.target}`, { kind: 'peer', sub: 'psc', cloud: 'gcp', owner: e.data.target.split('/')[1], nativeId: e.data.target,
      label: `PSC service ${e.data.target.split('/').pop()} (${e.data.target.split('/')[1]})`, yours: x.ownGcp(e.data.target.split('/')[1]), read: false, stub: true, cidrs: [] }).id;
    link(netNode(e.vpc).id, to, 'psc', { sub: e.id, name: e.name, nativeId: e.id, status: e.data.status, outside: !x.ownGcp(e.data.target.split('/')[1]), crossProject: e.data.target.split('/')[1] !== projectOf(e.vpc) });
  }
  // Shared VPCs (AWS RAM) and Shared VPC networks (Google Cloud): who runs what in them, and each member's part of
  // it (a slice, in its own account or project) joined to the VPC or network by a share line
  const AWS_PARTS = ['eni', 'sg', 'lb', 'endpoint', 'client-vpn', 'resolver-endpoint'], GCP_PARTS = ['instance', 'forwarding-rule', 'psc-endpoint', 'ilb'];
  // where a service project that runs nothing yet is drawn: its host's busiest network
  const busiest = new Map();
  for (const n of x.networks.values()) { const k = ginst.filter((i) => i.vpc === n.id).length, b = busiest.get(n.owner); if (!b || k > b.k || (k === b.k && n.name < b.name)) busiest.set(n.owner, { id: n.id, k, name: n.name }); }
  const runsInHost = (project, host) => x.items.some((i) => i.cloud === 'gcp' && i.owner === project && GCP_PARTS.includes(i.type) && projectOf(i.vpc) === host);
  for (const sh of x.shares?.values() || []) {
    const aws = sh.cloud === 'aws';
    let vn = nodes.get(aws ? `aws:vpc:${sh.owner}:${sh.vpc}` : `gcp:net:${sh.vpc}`);
    // a host network that is not read (its project is not connected): known from what service projects run in it
    if (!vn && !aws && [...sh.members.values()].some((m) => m.via.has('instances'))) vn = Object.assign(netNode(sh.vpc), { ownerNotRead: true });
    if (!vn || (aws && vn.stub)) continue;
    // a Shared VPC service project is in the host's organization (Google Cloud allows no other), so it is yours
    const name = (a) => (aws ? x.awsName(a) : x.gcpProjects.get(a)?.name || null), read = (a) => (aws ? x.awsAccounts.has(a) : x.gcpProjects.has(a)), yours = (a) => (aws ? x.ownAws(a) : true);
    const inIt = x.items.filter((i) => i.cloud === sh.cloud && i.vpc === sh.vpc && (i.vpcOwner || i.owner) === sh.owner && (aws ? AWS_PARTS : GCP_PARTS).includes(i.type));
    const exposedBy = (a) => x.exposures.filter((z) => z.cloud === sh.cloud && z.vpc === sh.vpc && (z.vpcOwner || z.owner) === sh.owner && z.owner === a && z.ports.length).length;
    const part = (a) => {
      const mine = inIt.filter((i) => i.owner === a);
      if (!aws) {
        const inst = mine.filter((i) => i.type === 'instance');
        return { instances: inst.length, externalIps: inst.filter((i) => i.data.interfaces.some((y) => y.natIps.length)).length,
          subnets: [...new Set(inst.flatMap((i) => i.data.interfaces.filter((y) => y.network === sh.vpc).map((y) => y.subnet)).filter(Boolean))],
          loadBalancers: mine.filter((i) => i.type === 'forwarding-rule' || i.type === 'ilb').length, endpoints: mine.filter((i) => i.type === 'psc-endpoint').length, exposed: exposedBy(a), runs: mine.length };
      }
      const enis = mine.filter((i) => i.type === 'eni');
      return { interfaces: enis.length, subnets: [...new Set(enis.map((i) => i.data.subnet).filter(Boolean))], securityGroups: mine.filter((i) => i.type === 'sg').length,
        loadBalancers: mine.filter((i) => i.type === 'lb').length, exposed: exposedBy(a), runs: mine.length };
    };
    vn.shared = true;
    vn.sharedWithPrincipals = sh.principals;
    vn.tenants = [{ account: sh.owner, name: name(sh.owner), owner: true, read: read(sh.owner) && !vn.ownerNotRead, ...part(sh.owner) },
      ...[...sh.members].map(([a, m]) => ({ account: a, name: name(a), owner: false, read: read(a), yours: yours(a), via: [...m.via].sort(), share: m.shareName || null, ...part(a) }))
        .sort((p, q) => q.runs - p.runs || p.account.localeCompare(q.account))];
    if (!aws) vn.sharedWith = vn.tenants.filter((t) => !t.owner).map((t) => t.account);
    // a slice for each member that is read and is there: it runs something there, it reads the VPC as shared with it
    // (AWS), or it is attached to the host and runs nothing in any of its networks yet (drawn on the busiest one)
    for (const t of vn.tenants.filter((y) => !y.owner && y.read)) {
      const idle = !aws && !t.runs && t.via.includes('xpn') && busiest.get(sh.owner)?.id === sh.vpc && !runsInHost(t.account, sh.owner);
      if (!(t.runs || (aws && t.via.includes('read')) || idle)) continue;
      const s = node(`${sh.cloud}:slice:${t.account}:${sh.vpc}`, { kind: 'slice', cloud: sh.cloud, owner: t.account, nativeId: sh.vpc, vpcOwner: sh.owner, region: vn.region || null, label: vn.label,
        ownerName: name(t.account), yours: t.yours, read: true, cidrs: vn.cidrs, vpcLabel: vn.label, vpcOwnerName: (aws && name(sh.owner)) || sh.owner, attachedOnly: idle, exposed: t.exposed,
        ...(aws ? { interfaces: t.interfaces, securityGroups: t.securityGroups, subnets: { total: t.subnets.length, public: t.subnets.filter((id) => x.publicSubnet.get(`${sh.owner}|${id}`)).length } }
          : { instances: t.instances, externalIps: t.externalIps, subnets: { total: t.subnets.length, public: 0 } }) });
      Object.assign(link(s.id, vn.id, 'share', { name: t.share || (aws ? 'shared VPC' : 'Shared VPC'), [aws ? 'crossAccount' : 'crossProject']: true, outside: !t.yours,
        ...(aws ? { interfaces: t.interfaces } : { instances: t.instances, attachedOnly: idle }) }), { from: s.id, to: vn.id });
    }
  }
  return { nodes: [...nodes.values()], links: [...links.values()] };
}
