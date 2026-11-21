// Watch → Networking (the Networking extension): how VPCs and networks connect, in AWS and Google Cloud and between
// them, what the internet can reach, and what is wrong with it.
//   Map:       AWS accounts on the left, Google Cloud projects on the right, each with its VPCs or networks; the
//              internet, transit gateways, VPN peers and networks outside your estate in the middle. Lines are peering,
//              transit gateway attachments, VPNs (AWS to Google Cloud matched by tunnel addresses), Interconnect and the
//              internet. Click anything for what is inside it.
//   Exposure:  every public address and the ports the internet reaches on it, through which rule.
//   Findings:  open ports, default networks, flow logs, outsiders, tunnels down; reviewers mark them expected.
//   Inventory: everything read, searchable.
import { h, svg, get, post, api, ago, num, toast, busy, syncUrl, tile, searchBox, loadEnvironments, envs, copy } from '../lib.js';
import { session } from '../main.js';

const TABS = [['map', 'Map'], ['exposure', 'Exposure'], ['findings', 'Findings'], ['inventory', 'Inventory']];
const SEV = { high: 0, medium: 1, low: 2, none: 3 };
const RED = 'var(--red)', AMBER = 'var(--amber)';
const sevColor = (s) => (s === 'high' ? RED : s === 'medium' ? AMBER : 'var(--edge)');
const LINK = { peering: ['Peering', 'var(--blue)'], tgw: ['Transit gateway', 'var(--green)'], 'tgw-peering': ['Transit gateway peering', 'var(--green)'], vpn: ['VPN', 'var(--banana)'],
  interconnect: ['Interconnect', '#c59bff'], internet: ['Internet', 'var(--faint)'] };
const KIND = { vpc: 'VPC', network: 'NETWORK', tgw: 'TRANSIT GATEWAY', peer: 'PEER', internet: 'INTERNET' };
const CLOUD = { aws: 'AWS', gcp: 'Google Cloud' };
const TYPE_LABEL = { vpc: 'VPCs', subnet: 'Subnets', 'route-table': 'Route tables', igw: 'Internet gateways', eigw: 'Egress-only gateways', nat: 'NAT gateways', sg: 'Security groups', nacl: 'Network ACLs',
  peering: 'VPC peering', tgw: 'Transit gateways', 'tgw-attachment': 'Transit gateway attachments', vpn: 'Site-to-site VPNs', cgw: 'Customer gateways', vgw: 'Virtual private gateways', endpoint: 'VPC endpoints',
  eni: 'Network interfaces', 'flow-log': 'Flow logs', firewall: 'Firewalls / firewall rules', lb: 'Load balancers', network: 'Networks (Google Cloud)', 'firewall-policy': 'Firewall policies', router: 'Cloud Routers',
  route: 'Routes', 'vpn-gateway': 'VPN gateways', 'peer-vpn-gateway': 'Peer VPN gateways', 'vpn-tunnel': 'VPN tunnels', interconnect: 'Interconnect attachments', address: 'External addresses',
  'forwarding-rule': 'Forwarding rules', instance: 'Instances' };

// a security group rule or firewall rule in one line
const awsRule = (r) => `${r.proto === 'all' ? 'all traffic' : `${r.proto} ${r.from == null ? 'all' : r.from === r.to ? r.from : `${r.from}-${r.to}`}`} ← ${[...r.cidrs, ...r.ipv6, ...r.groups.map((g) => g.id + (g.account ? '' : '')), ...r.prefixLists].join(', ') || 'nothing'}`;
const world = (list) => list.some((c) => c === '0.0.0.0/0' || c === '::/0');
const gcpRule = (f) => `${f.action} ${f.rules.map((x) => `${x.proto}${x.ports.length ? `:${x.ports.join(',')}` : ''}`).join(' ')} ${f.direction === 'INGRESS' ? `← ${[...f.sourceRanges, ...f.sourceTags.map((t) => `tag ${t}`), ...f.sourceServiceAccounts].join(', ') || 'any'}` : `→ ${f.destinationRanges.join(', ') || 'any'}`}`;

export async function networkPage(ctx) {
  ctx.setCrumbs('Watch', 'Networking');
  const P = ctx.params;
  const f = { tab: TABS.some(([k]) => k === P.get('tab')) ? P.get('tab') : 'map', cloud: ['aws', 'gcp'].includes(P.get('cloud')) ? P.get('cloud') : '', q: P.get('q') || '', sel: P.get('sel') || '',
    internet: P.get('internet') !== '0', fsev: P.get('severity') || '', ftype: P.get('type') || '', fstatus: P.get('status') === 'resolved' ? 'resolved' : 'open' };
  await loadEnvironments().catch(() => []);
  const envColor = (id) => envs().find((e) => e.id === id)?.color || 'var(--edge)';
  const envName = (id) => envs().find((e) => e.id === id)?.name || id || '';
  let d = await get('/network');
  const body = h('div');
  const panel = h('aside', { class: 'card net-panel', 'aria-live': 'polite' });
  const toUrl = () => syncUrl({ tab: f.tab === 'map' ? '' : f.tab, cloud: f.cloud, q: f.q, sel: f.sel, internet: f.internet ? '' : '0', severity: f.fsev, type: f.ftype, status: f.fstatus === 'open' ? '' : f.fstatus });

  // ---------------------------------------------------------------- header
  const reads = () => {
    const ok = d.reads.filter((r) => !r.error), bad = d.reads.filter((r) => r.error), skip = d.reads.filter((r) => r.skipped?.length);
    const last = d.reads.map((r) => r.readAt).sort().pop();
    return h('div', { class: 'small muted net-reads' },
      d.reads.length ? `Read ${ago(last)} · ${ok.filter((r) => r.cloud === 'aws').length} AWS account${ok.filter((r) => r.cloud === 'aws').length === 1 ? '' : 's'} · ${ok.filter((r) => r.cloud === 'gcp').length} Google Cloud project${ok.filter((r) => r.cloud === 'gcp').length === 1 ? '' : 's'}` : 'Not read yet',
      (bad.length || skip.length) ? h('details', { class: 'net-skips' }, h('summary', null, `${bad.length ? `${bad.length} not read` : ''}${bad.length && skip.length ? ' · ' : ''}${skip.length ? `${skip.length} with reads skipped` : ''}`),
        h('ul', { class: 'tiny' }, [...bad.map((r) => h('li', null, h('b', null, `${r.name}: `), r.error)), ...skip.map((r) => h('li', null, h('b', null, `${r.name}: `), `not allowed to call ${r.skipped.join(', ')}. Add ${r.cloud === 'aws' ? 'them to the scanner role (Accounts → Edit shows the policy)' : 'them to the reader role (Google Cloud setup)'}.`))])) : null);
  };
  const readBtn = h('button', { class: 'btn sm' }, 'Read now');
  if (!session.user?.permissions.includes('scan')) readBtn.hidden = true;
  readBtn.addEventListener('click', () => busy(readBtn, async () => { await post('/network/read'); toast('Networking will be read again within a minute'); }));
  const head = h('header', { class: 'head' },
    h('div', null, h('div', { class: 'eyebrow' }, 'WATCH · NETWORKING · EXTENSION'), h('h1', null, 'Networking'),
      h('p', { class: 'small muted', style: 'max-width:820px' }, 'How your VPCs and networks connect, inside each cloud and between AWS and Google Cloud, what the internet can reach, and what is wrong with it. Read from VPCs, subnets, route tables, internet and NAT gateways, security groups, network ACLs, firewalls, peering, transit gateways and VPNs.')),
    h('div', { class: 'stack', style: 'align-items:flex-end;gap:8px' }, reads(), readBtn));
  const exposed = d.exposures.filter((e) => e.ports.length);
  const tiles = h('div', { class: 'tiles' },
    tile('Reachable from the internet', num(exposed.length), `${exposed.filter((e) => e.severity === 'high').length} on admin or database ports`, { bad: exposed.some((e) => e.severity === 'high'), onClick: () => setTab('exposure') }),
    tile('Findings · high', num(d.findings.high), 'click for the list', { bad: d.findings.high > 0, onClick: () => { f.fsev = 'high'; setTab('findings'); } }),
    tile('Findings · medium', num(d.findings.medium), 'click for the list', { onClick: () => { f.fsev = 'medium'; setTab('findings'); } }),
    tile('VPCs and networks', num(d.nodes.filter((n) => (n.kind === 'vpc' || n.kind === 'network') && !n.stub).length), `${d.owners.filter((o) => o.cloud === 'aws').length} accounts · ${d.owners.filter((o) => o.cloud === 'gcp').length} projects`),
    tile('Connections', num(d.links.filter((l) => l.kind !== 'internet').length), `${d.links.filter((l) => l.cross).length} between AWS and Google Cloud`));
  const tabsEl = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Networking' });
  const drawTabs = () => tabsEl.replaceChildren(...TABS.map(([k, l]) => h('button', { role: 'tab', type: 'button', 'aria-selected': String(f.tab === k), onClick: () => setTab(k) },
    l, k === 'findings' && d.findings.high + d.findings.medium ? h('span', { class: 'rail-count', style: 'position:static;margin-left:6px' }, String(d.findings.high + d.findings.medium)) : null)));
  function setTab(k) { f.tab = k; drawTabs(); draw(); }

  // ---------------------------------------------------------------- the detail panel
  const sect = (title, ...kids) => h('section', { class: 'net-sect' }, h('h3', { class: 'small' }, title), ...kids);
  const kv = (rows) => h('dl', { class: 'net-kv' }, rows.filter(Boolean).flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  const nodeName = (id) => d.nodes.find((n) => n.id === id)?.label || id;
  const findingRows = (list) => list.length ? h('div', { class: 'stack', style: 'gap:6px' }, list.map((x) => h('div', { class: `net-f sev-${x.severity}` }, h('span', { class: `badge b-${x.severity}` }, x.severity), ' ', h('b', { class: 'small' }, x.title), h('div', { class: 'tiny muted' }, x.detail))))
    : h('p', { class: 'small muted' }, 'None open.');
  const linkLine = (l) => {
    const [label, color] = LINK[l.kind] || [l.kind, 'var(--muted)'];
    const status = l.kind === 'vpn' ? `${l.up ?? 0}/${l.tunnels?.length || 0} tunnels up` : l.kind === 'internet' ? `out: ${l.egress || '—'}${l.ingress ? ` · ${l.ingress} reachable from it` : ''}` : l.status || '';
    return h('button', { class: 'net-link-row', type: 'button', onClick: () => pick(l.id) }, h('span', { class: 'net-swatch', style: `background:${color}` }), h('b', { class: 'small' }, label), ' ',
      h('span', { class: 'small' }, l.other?.label || nodeName(l.from === f.sel ? l.to : l.from)), h('span', { class: 'tiny muted' }, ` ${status}${l.outside ? ' · outside your estate' : ''}${l.cross ? ' · across clouds' : ''}`));
  };
  async function drawPanel() {
    if (!f.sel) { panel.replaceChildren(overview()); return; }
    const link = d.links.find((l) => l.id === f.sel);
    if (link) { panel.replaceChildren(linkPanel(link)); return; }
    const n = d.nodes.find((x) => x.id === f.sel);
    if (!n) { f.sel = ''; panel.replaceChildren(overview()); return; }
    if (n.kind === 'internet' || n.kind === 'peer' || n.stub) { panel.replaceChildren(simpleNode(n)); return; }
    panel.replaceChildren(h('div', { class: 'muted small', style: 'padding:14px' }, 'Loading…'));
    const want = f.sel;
    let x; try { x = await get(`/network/node?id=${encodeURIComponent(n.id)}`); } catch (e) { panel.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    if (f.sel !== want) return;
    panel.replaceChildren(nodePanel(x));
  }
  const close = h('button', { class: 'btn sm', onClick: () => pick('') }, 'Close');
  function overview() {
    const worst = [...exposed].slice(0, 6);
    return h('div', { class: 'stack', style: 'gap:12px;padding:14px' },
      h('div', { class: 'eyebrow' }, 'OVERVIEW'),
      h('p', { class: 'small' }, `${num(d.nodes.filter((n) => n.kind === 'vpc' && !n.stub).length)} VPCs in AWS and ${num(d.nodes.filter((n) => n.kind === 'network' && !n.stub).length)} networks in Google Cloud. ${num(d.links.filter((l) => l.cross).length)} connection${d.links.filter((l) => l.cross).length === 1 ? '' : 's'} between the clouds, ${num(d.links.filter((l) => l.outside).length)} with networks outside your estate. Click a VPC, a network or a line for what is in it.`),
      sect('Reachable from the internet first', worst.length ? h('div', { class: 'stack', style: 'gap:6px' }, worst.map((e) => h('button', { class: 'net-link-row', type: 'button', onClick: () => pick(nodeOfExposure(e)) },
        h('span', { class: `badge b-${e.severity === 'none' ? 'neutral' : e.severity}` }, e.severity === 'none' ? 'closed' : e.severity), ' ', h('b', { class: 'small' }, e.name),
        h('span', { class: 'tiny muted' }, ` ${e.addresses.join(', ')} · ${e.ports.map((p) => p.ports).join(', ')}`)))) : h('p', { class: 'small muted' }, 'Nothing reachable.')),
      sect('Legend', h('div', { class: 'stack', style: 'gap:4px' }, Object.entries(LINK).map(([, [l, c]]) => h('div', { class: 'small' }, h('span', { class: 'net-swatch', style: `background:${c}` }), ' ', l)),
        h('div', { class: 'small' }, h('span', { class: 'net-swatch', style: `background:${RED}` }), ' red border: a high finding; amber: medium. Dashed: down or not routed.'))));
  }
  const nodeOfExposure = (e) => (e.cloud === 'aws' ? `aws:vpc:${e.owner}:${e.vpc}` : `gcp:net:${e.vpc}`);
  function simpleNode(n) {
    const ls = d.links.filter((l) => l.from === n.id || l.to === n.id);
    return h('div', { class: 'stack', style: 'gap:12px;padding:14px' },
      h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'eyebrow' }, n.kind === 'internet' ? 'THE INTERNET' : n.kind === 'peer' ? 'VPN OR INTERCONNECT PEER' : `${KIND[n.kind]} · NOT READ`), close),
      h('b', { class: 'name' }, n.label),
      n.kind === 'peer' && h('p', { class: 'small muted' }, `${n.ip ? `${n.ip}: ` : ''}a device outside AWS and Google Cloud as read here (an office, a data centre, another cloud), or a gateway in an account or project no connection reads.`),
      n.stub && h('p', { class: 'small muted' }, `${CLOUD[n.cloud]} ${n.cloud === 'aws' ? 'account' : 'project'} ${n.owner}${n.ownerName ? ` (${n.ownerName})` : ''}: ${n.yours ? 'yours, but not read here, so what is inside is not known.' : 'not yours. Only what your side says about the link is known.'}${n.cidrs?.length ? ` Address range: ${n.cidrs.join(', ')}.` : ''}`),
      n.kind === 'internet' && h('p', { class: 'small muted' }, 'Each line is a VPC or network with a way out (internet gateway, NAT, a default internet route, external addresses); the number on it is how many addresses in it the internet can reach. The Exposure tab lists them.'),
      sect(`Connections (${ls.length})`, h('div', { class: 'stack', style: 'gap:4px' }, ls.map((l) => linkLine({ ...l, other: d.nodes.find((x) => x.id === (l.from === n.id ? l.to : l.from)) })))));
  }
  function linkPanel(l) {
    const a = d.nodes.find((n) => n.id === l.from), b = d.nodes.find((n) => n.id === l.to), [label, color] = LINK[l.kind] || [l.kind];
    const rows = [['From', a?.label], ['To', b?.label], l.name && ['Name', l.name], l.nativeId && ['ID', h('span', { class: 'mono tiny' }, l.nativeId)], l.status && ['State', l.status],
      l.kind === 'peering' && l.routed != null && ['Routed', l.routed ? 'yes, a route table sends traffic over it' : 'no route table sends traffic over it yet'],
      (l.crossAccount || l.crossProject) && ['Across', l.crossAccount ? 'two AWS accounts' : 'two Google Cloud projects'], l.outside && ['Outside your estate', h('span', { class: 'badge b-medium' }, 'yes')],
      l.kind === 'internet' && ['Way out', l.egress], l.kind === 'internet' && ['Reachable from it', `${l.ingress || 0} address${l.ingress === 1 ? '' : 'es'}`], l.gateway && ['Google Cloud gateway', `${l.gateway} (${(l.gatewayIps || []).join(', ')})`]];
    return h('div', { class: 'stack', style: 'gap:12px;padding:14px' },
      h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'eyebrow' }, `${label.toUpperCase()}${l.cross ? ' · AWS ↔ GOOGLE CLOUD' : ''}`), close),
      h('b', { class: 'name' }, `${a?.label || l.from} ↔ ${b?.label || l.to}`), h('div', { class: 'net-swatch wide', style: `background:${color}` }), kv(rows),
      l.tunnels?.length > 0 && sect('Tunnels', h('table', { class: 'net-table' }, h('thead', null, h('tr', null, ['AWS end', '', 'Google Cloud', ''].map((x) => h('th', null, x)))),
        h('tbody', null, l.tunnels.map((t) => h('tr', null, h('td', { class: 'mono tiny' }, t.aws || t.peer || '—'), h('td', null, t.awsStatus ? h('span', { class: `badge ${t.awsStatus === 'UP' ? 'b-green' : 'b-high'}` }, t.awsStatus === 'UP' ? 'up' : 'down') : ''),
          h('td', { class: 'tiny' }, t.gcp || '—'), h('td', null, t.gcpStatus ? h('span', { class: `badge ${t.gcpStatus === 'ESTABLISHED' ? 'b-green' : 'b-high'}`, title: t.gcpStatus }, t.gcpStatus === 'ESTABLISHED' ? 'up' : 'down') : '')))))),
      l.vpns?.length > 0 && sect('AWS VPN connections', h('ul', { class: 'small' }, l.vpns.map((v) => h('li', null, `${v.name} (${v.id}) to ${v.cgw || 'unknown address'} · ${v.state}`)))),
      h('div', { class: 'row' }, a && !a.stub && a.kind !== 'internet' && h('button', { class: 'btn sm', onClick: () => pick(a.id) }, `Open ${a.label}`), b && !b.stub && b.kind !== 'internet' && h('button', { class: 'btn sm', onClick: () => pick(b.id) }, `Open ${b.label}`)));
  }
  function nodePanel(x) {
    const n = x.node;
    const headRow = h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'eyebrow' }, `${KIND[n.kind]} · ${CLOUD[n.cloud] || ''} · ${n.ownerLabel || n.owner}${n.region ? ` · ${n.region}` : ''}`), close);
    const conns = sect(`Connections (${x.links.length})`, x.links.length ? h('div', { class: 'stack', style: 'gap:4px' }, x.links.map(linkLine)) : h('p', { class: 'small muted' }, 'Not connected to anything.'));
    const exp = x.exposures.length ? sect(`Reachable from the internet (${x.exposures.filter((e) => e.ports.length).length})`, exposureTable(x.exposures, false)) : null;
    const finds = sect(`Findings (${x.findings.length})`, findingRows(x.findings));
    if (n.kind === 'vpc') {
      const pub = x.subnets.filter((s) => s.public).length;
      return h('div', { class: 'stack', style: 'gap:12px;padding:14px' }, headRow,
        h('div', { class: 'row' }, h('b', { class: 'name' }, n.label), n.isDefault && h('span', { class: 'badge b-neutral' }, 'default VPC')),
        h('div', { class: 'row tiny muted' }, h('span', { class: 'mono' }, n.nativeId), h('button', { class: 'btn sm', onClick: () => copy(n.nativeId) }, 'Copy ID')),
        kv([['Address range', n.cidrs.join(', ')], ['Subnets', `${x.subnets.length}: ${pub} public, ${x.subnets.length - pub} private`], ['Internet gateway', n.igw || 'none'],
          ['NAT', n.nats ? `${n.nats}${n.natIps?.length ? ` (${n.natIps.join(', ')})` : ''}` : 'none'], ['Flow logs', x.flowLogs ? 'on' : h('span', { class: 'badge b-medium' }, 'off')],
          ['Network Firewall', x.firewalls.length ? x.firewalls.map((y) => y.name).join(', ') : 'none'], ['Endpoints', x.endpoints.length ? x.endpoints.map((e) => `${e.service.split('.').pop()} (${e.kind.toLowerCase()})`).join(', ') : 'none']]),
        finds, exp, conns,
        sect(`Subnets (${x.subnets.length})`, h('table', { class: 'net-table' }, h('thead', null, h('tr', null, ['Subnet', 'Range', 'Zone', '', 'In it'].map((y) => h('th', null, y)))),
          h('tbody', null, x.subnets.map((s) => h('tr', null, h('td', { class: 'small' }, s.name, h('div', { class: 'mono tiny muted' }, s.id)), h('td', { class: 'mono tiny' }, s.cidr), h('td', { class: 'tiny' }, s.az || ''),
            h('td', null, h('span', { class: `badge ${s.public ? 'b-amber' : 'b-neutral'}` }, s.public ? 'public' : 'private'), s.mapPublicIp && h('div', { class: 'tiny muted' }, 'auto public IP')), h('td', { class: 'tiny' }, num(s.interfaces))))))),
        h('details', null, h('summary', { class: 'small' }, `Security groups (${x.securityGroups.length})`), h('div', { class: 'stack', style: 'gap:8px;margin-top:8px' }, x.securityGroups.map((g) => h('div', { class: 'net-rule-box' },
          h('div', { class: 'row' }, h('b', { class: 'small' }, g.name), h('span', { class: 'mono tiny muted' }, g.id), h('span', { class: 'tiny muted' }, g.used ? `used by ${g.used}` : 'not used')),
          g.ingress.length ? h('ul', { class: 'tiny mono' }, g.ingress.map((r) => h('li', { class: world([...r.cidrs, ...r.ipv6]) ? 'net-world' : '' }, `in  ${awsRule(r)}`))) : h('div', { class: 'tiny muted' }, 'no inbound rules'))))),
        h('details', null, h('summary', { class: 'small' }, `Route tables (${x.routeTables.length})`), h('div', { class: 'stack', style: 'gap:8px;margin-top:8px' }, x.routeTables.map((t) => h('div', { class: 'net-rule-box' },
          h('div', { class: 'row' }, h('b', { class: 'small' }, t.name), t.main && h('span', { class: 'badge b-neutral' }, 'main'), h('span', { class: 'tiny muted' }, `${t.subnets.length} subnet${t.subnets.length === 1 ? '' : 's'}`)),
          h('ul', { class: 'tiny mono' }, t.routes.map((r) => h('li', { class: r.state === 'blackhole' ? 'net-world' : '' }, `${r.dest} → ${r.target.type === 'local' ? 'local' : `${r.target.type} ${r.target.id || ''}`}${r.state === 'blackhole' ? ' (blackhole)' : ''}`))))))),
        h('details', null, h('summary', { class: 'small' }, `Network ACLs (${x.nacls.length})`), h('div', { class: 'stack', style: 'gap:8px;margin-top:8px' }, x.nacls.map((a) => h('div', { class: 'net-rule-box' },
          h('div', { class: 'row' }, h('b', { class: 'small' }, a.name), a.isDefault && h('span', { class: 'badge b-neutral' }, 'default')),
          h('ul', { class: 'tiny mono' }, a.entries.filter((e) => !e.egress).map((e) => h('li', { class: e.action === 'allow' && world([e.cidr]) ? 'net-world' : '' }, `in #${e.n} ${e.action} ${e.proto}${e.from != null ? ` ${e.from}-${e.to}` : ''} ← ${e.cidr}`))))))),
        x.gateways.length > 0 && sect('Gateways', h('ul', { class: 'small' }, x.gateways.map((g) => h('li', null, `${g.type.toUpperCase()} ${g.name !== g.id ? `${g.name} ` : ''}`, h('span', { class: 'mono tiny muted' }, g.id), g.detail ? ` · ${g.detail}` : '')))),
        x.loadBalancers.length > 0 && sect('Load balancers', h('ul', { class: 'small' }, x.loadBalancers.map((b) => h('li', null, `${b.name} · ${b.kind} · ${b.scheme} · ${b.listeners.map((l) => `${l.proto} ${l.port}`).join(', ')}`)))),
        h('details', null, h('summary', { class: 'small' }, `Network interfaces (${x.interfaces.length})`), h('table', { class: 'net-table' }, h('tbody', null, x.interfaces.map((e) => h('tr', null,
          h('td', { class: 'small' }, e.instance || e.name, h('div', { class: 'mono tiny muted' }, e.id)), h('td', { class: 'mono tiny' }, e.privateIp || ''), h('td', { class: 'mono tiny' }, e.publicIp || ''), h('td', { class: 'tiny' }, e.groups.join(', '))))))));
    }
    if (n.kind === 'network') {
      return h('div', { class: 'stack', style: 'gap:12px;padding:14px' }, headRow,
        h('div', { class: 'row' }, h('b', { class: 'name' }, n.label), x.auto && h('span', { class: 'badge b-medium' }, 'auto subnets')),
        h('div', { class: 'row tiny muted' }, h('span', { class: 'mono' }, n.nativeId), h('button', { class: 'btn sm', onClick: () => copy(n.nativeId) }, 'Copy')),
        kv([['Routing', x.routingMode || '—'], ['Subnets', `${x.subnets.length} in ${[...new Set(x.subnets.map((s) => s.region))].length} region${[...new Set(x.subnets.map((s) => s.region))].length === 1 ? '' : 's'}`],
          ['Cloud NAT', x.routers.flatMap((r) => r.nats.map((m) => `${m.name} (${r.region})`)).join(', ') || 'none'], ['Instances', `${x.instances.length}, ${x.instances.filter((i) => i.interfaces.some((y) => y.natIps.length)).length} with an external address`],
          n.sharedWith?.length && ['Used by projects', n.sharedWith.join(', ')]]),
        finds, exp, conns,
        sect(`Firewall rules (${x.firewallRules.length})`, h('div', { class: 'stack', style: 'gap:4px' }, x.firewallRules.map((r) => h('div', { class: `net-rule-box${r.direction === 'INGRESS' && r.action === 'allow' && world(r.sourceRanges) && !r.disabled ? ' net-world-box' : ''}` },
          h('div', { class: 'row' }, h('b', { class: 'small' }, r.name), h('span', { class: 'tiny muted' }, `priority ${r.priority}${r.disabled ? ' · disabled' : ''}${r.logging ? ' · logged' : ''}`)),
          h('div', { class: 'tiny mono' }, gcpRule(r)), (r.targetTags.length || r.targetServiceAccounts.length) ? h('div', { class: 'tiny muted' }, `targets: ${[...r.targetTags.map((t) => `tag ${t}`), ...r.targetServiceAccounts].join(', ')}`) : h('div', { class: 'tiny muted' }, 'targets: every instance'))))),
        x.firewallPolicies.length > 0 && sect('Firewall policies', h('ul', { class: 'small' }, x.firewallPolicies.map((p) => h('li', null, `${p.name}: ${p.rules.length} rules`)))),
        sect(`Subnets (${x.subnets.length})`, h('table', { class: 'net-table' }, h('thead', null, h('tr', null, ['Subnet', 'Region', 'Range', 'Flow logs', 'Private Google access'].map((y) => h('th', null, y)))),
          h('tbody', null, x.subnets.map((s) => h('tr', null, h('td', { class: 'small' }, s.name), h('td', { class: 'tiny' }, s.region), h('td', { class: 'mono tiny' }, s.cidr),
            h('td', null, h('span', { class: `badge ${s.flowLogs ? 'b-green' : 'b-neutral'}` }, s.flowLogs ? 'on' : 'off')), h('td', { class: 'tiny' }, s.privateGoogleAccess ? 'on' : 'off')))))),
        x.routers.length > 0 && sect('Cloud Routers', h('ul', { class: 'small' }, x.routers.map((r) => h('li', null, `${r.name} (${r.region})${r.asn ? ` · ASN ${r.asn}` : ''}${r.peers.length ? ` · ${r.peers.length} BGP peers` : ''}${r.nats.length ? ` · NAT ${r.nats.map((m) => m.name).join(', ')}` : ''}`)))),
        h('details', null, h('summary', { class: 'small' }, `Instances (${x.instances.length})`), h('table', { class: 'net-table' }, h('tbody', null, x.instances.map((i) => h('tr', null,
          h('td', { class: 'small' }, i.name, h('div', { class: 'tiny muted' }, `${i.owner} · ${i.zone}`)), h('td', { class: 'mono tiny' }, i.interfaces.map((y) => y.ip).join(', ')),
          h('td', { class: 'mono tiny' }, i.interfaces.flatMap((y) => y.natIps).join(', ')), h('td', { class: 'tiny' }, i.tags.join(', '))))))));
    }
    return h('div', { class: 'stack', style: 'gap:12px;padding:14px' }, headRow, h('b', { class: 'name' }, n.label), h('div', { class: 'mono tiny muted' }, n.nativeId),
      x.attachments && sect(`Attachments (${x.attachments.length})`, h('table', { class: 'net-table' }, h('tbody', null, x.attachments.map((a) => h('tr', null,
        h('td', { class: 'small' }, a.resourceType), h('td', { class: 'mono tiny' }, a.resourceId), h('td', { class: 'tiny' }, `account ${a.resourceOwner}`), h('td', { class: 'tiny' }, a.state)))))), finds, conns);
  }
  function pick(id) { f.sel = f.sel === id && id ? '' : id; toUrl(); if (f.tab === 'map') redrawMap(); drawPanel(); }

  // ---------------------------------------------------------------- the map
  const COL = 548, MID = 250, GAP = 44, NW = 252, NH = 94, PAD = 14, HEAD = 40;
  const X_AWS = 0, X_MID = COL + GAP, X_GCP = COL + GAP + MID + GAP, WIDTH = X_GCP + COL;
  let view = null, layout = null;
  function computeLayout() {
    const pos = new Map(), cards = [];
    const shown = (n) => !f.cloud || !n.cloud || n.cloud === f.cloud || n.kind === 'peer';
    const placeCloud = (cloud, x0) => {
      let y = 110;
      for (const o of d.owners.filter((o) => o.cloud === cloud && (!f.cloud || f.cloud === cloud))) {
        const list = d.nodes.filter((n) => n.cloud === cloud && n.owner === o.owner && !n.stub && (n.kind === 'vpc' || n.kind === 'network'))
          .sort((a, b) => (a.isDefault ? 1 : 0) - (b.isDefault ? 1 : 0) || (SEV[a.worst] ?? 3) - (SEV[b.worst] ?? 3) || a.label.localeCompare(b.label));
        if (!list.length) continue;
        const rows = Math.ceil(list.length / 2), hgt = HEAD + rows * (NH + 14) + PAD - 14 + PAD;
        cards.push({ x: x0, y, w: COL, h: hgt, owner: o });
        list.forEach((n, i) => pos.set(n.id, { x: x0 + PAD + (i % 2) * (NW + 16), y: y + HEAD + Math.floor(i / 2) * (NH + 14), w: NW, h: NH }));
        y += hgt + 22;
      }
      return y;
    };
    const yA = placeCloud('aws', X_AWS), yG = placeCloud('gcp', X_GCP);
    // the middle: internet on top, transit gateways, then everything not read (peers, outside networks)
    if (f.internet && d.nodes.some((n) => n.kind === 'internet')) pos.set('internet', { x: X_MID + 25, y: 4, w: MID - 50, h: 52 });
    let y = 110;
    const midNodes = d.nodes.filter((n) => shown(n) && (n.kind === 'tgw' || n.kind === 'peer' || n.stub)).sort((a, b) => (a.kind === 'tgw' ? 0 : 1) - (b.kind === 'tgw' ? 0 : 1) || (a.kind === 'peer' ? 1 : 0) - (b.kind === 'peer' ? 1 : 0));
    for (const n of midNodes) { pos.set(n.id, { x: X_MID, y, w: MID, h: 76 }); y += 94; }
    return { pos, cards, height: Math.max(yA, yG, y) + 20 };
  }
  const svgEl = svg('svg', { class: 'net-map', role: 'img', 'aria-label': 'Network map' });
  const mapWrap = h('div', { class: 'net-map-wrap' }, svgEl);
  // pan and zoom: drag to move, wheel to zoom about the pointer
  let drag = null;
  mapWrap.addEventListener('wheel', (e) => {
    e.preventDefault();
    const r = svgEl.getBoundingClientRect(), k = Math.exp(Math.sign(e.deltaY) * Math.min(0.25, Math.abs(e.deltaY) / 400));
    const px = view.x + ((e.clientX - r.left) / r.width) * view.w, py = view.y + ((e.clientY - r.top) / r.height) * view.h;
    const w = Math.max(300, Math.min(WIDTH * 3, view.w * k)), hh = (w / view.w) * view.h;
    view = { x: px - ((px - view.x) * w) / view.w, y: py - ((py - view.y) * hh) / view.h, w, h: hh }; applyView();
  }, { passive: false });
  mapWrap.addEventListener('pointerdown', (e) => { if (e.target.closest('.net-node, .net-hit')) return; drag = { x: e.clientX, y: e.clientY, v: { ...view } }; mapWrap.setPointerCapture(e.pointerId); mapWrap.classList.add('grabbing'); });
  mapWrap.addEventListener('pointermove', (e) => { if (!drag) return; const r = svgEl.getBoundingClientRect(); view = { ...drag.v, x: drag.v.x - ((e.clientX - drag.x) / r.width) * drag.v.w, y: drag.v.y - ((e.clientY - drag.y) / r.height) * drag.v.h }; applyView(); });
  mapWrap.addEventListener('pointerup', () => { drag = null; mapWrap.classList.remove('grabbing'); });
  const applyView = () => svgEl.setAttribute('viewBox', `${view.x} ${view.y} ${view.w} ${view.h}`);
  const fit = () => { const r = mapWrap.getBoundingClientRect(), aspect = (r.height || 640) / (r.width || 1000); const w = WIDTH + 240; view = { x: -120, y: -8, w, h: Math.max(layout.height + 20, w * aspect) }; applyView(); };
  const zoom = (k) => { const cx = view.x + view.w / 2, cy = view.y + view.h / 2, w = view.w * k, hh = view.h * k; view = { x: cx - w / 2, y: cy - hh / 2, w, h: hh }; applyView(); };

  const anchor = (p, toward) => {
    const cx = p.x + p.w / 2, cy = p.y + p.h / 2;
    if (toward == null) return [cx, cy];
    if (Math.abs(toward[0] - cx) > p.w / 2 + 10) return [toward[0] > cx ? p.x + p.w : p.x, cy];
    return [cx, toward[1] > cy ? p.y + p.h : p.y];
  };
  function redrawMap() {
    const { pos, cards } = layout;
    const q = f.q.toLowerCase();
    const match = (n) => !q || `${n.label} ${n.nativeId || ''} ${n.ownerLabel || ''} ${n.owner || ''} ${(n.cidrs || []).join(' ')}`.toLowerCase().includes(q);
    const rel = new Set();
    if (f.sel) { rel.add(f.sel); for (const l of d.links) if (l.id === f.sel || l.from === f.sel || l.to === f.sel) { rel.add(l.id); rel.add(l.from); rel.add(l.to); } }
    const dim = (id) => (f.sel && !rel.has(id) ? 0.18 : 1);
    const g = [];
    for (const c of cards) {
      const o = c.owner;
      g.push(svg('g', { class: 'net-card' }, svg('rect', { x: c.x, y: c.y, width: c.w, height: c.h, rx: 3, class: 'net-card-bg' }),
        svg('rect', { x: c.x, y: c.y, width: 4, height: c.h, fill: envColor(o.environment) }),
        svg('text', { x: c.x + 14, y: c.y + 17, class: 'net-card-eyebrow' }, `${o.cloud === 'aws' ? 'AWS ACCOUNT' : 'GOOGLE CLOUD PROJECT'}${o.environment ? ` · ${envName(o.environment).toUpperCase()}` : ''}`),
        svg('text', { x: c.x + 14, y: c.y + 32, class: 'net-card-title' }, `${o.name}${o.cloud === 'aws' && o.name !== o.owner ? `  ·  ${o.owner}` : o.title && o.title !== o.name ? `  ·  ${o.title}` : ''}`)));
    }
    g.push(svg('text', { x: X_AWS, y: 80, class: 'net-col-title' }, f.cloud === 'gcp' ? '' : 'AWS'), svg('text', { x: X_GCP, y: 80, class: 'net-col-title' }, f.cloud === 'aws' ? '' : 'GOOGLE CLOUD'),
      svg('text', { x: X_MID + MID / 2, y: 80, class: 'net-col-title mid', 'text-anchor': 'middle' }, 'HUBS · PEERS · OUTSIDE'));
    // lines under the boxes
    const lines = [];
    for (const l of d.links) {
      if (l.kind === 'internet' && !f.internet) continue;
      const a = pos.get(l.from), b = pos.get(l.to); if (!a || !b) continue;
      const ca = [a.x + a.w / 2, a.y + a.h / 2], cb = [b.x + b.w / 2, b.y + b.h / 2];
      const [x1, y1] = anchor(a, cb), [x2, y2] = anchor(b, ca);
      const same = Math.abs(ca[0] - cb[0]) < 40, side = ca[0] < X_MID ? -1 : 1;
      const path = same ? `M${x1 - (side < 0 ? a.w / 2 : -a.w / 2) + (side < 0 ? 0 : 0)},${ca[1]} C${ca[0] + side * (a.w / 2 + 70)},${ca[1]} ${cb[0] + side * (b.w / 2 + 70)},${cb[1]} ${cb[0] + side * (b.w / 2)},${cb[1]}`
        : `M${x1},${y1} C${x1 + (x2 - x1) * 0.45},${y1} ${x2 - (x2 - x1) * 0.45},${y2} ${x2},${y2}`;
      const down = l.kind === 'vpn' && (l.up ?? 0) < (l.tunnels?.length || 0), none = l.kind === 'vpn' && !l.up;
      const exposedBad = l.kind === 'internet' && l.ingress > 0 && d.nodes.find((n) => n.id === l.from)?.worst === 'high';
      const color = none ? RED : exposedBad ? RED : l.outside ? AMBER : (LINK[l.kind] || [, 'var(--muted)'])[1];
      const width = f.sel === l.id ? 3.5 : l.cross ? 2.6 : l.kind === 'internet' ? 1.1 : 1.8;
      const dash = none || (l.kind === 'peering' && l.routed === false) ? '6 5' : l.kind === 'internet' ? '2 4' : null;
      lines.push(svg('g', { opacity: dim(l.id) },
        svg('path', { d: path, fill: 'none', stroke: color, 'stroke-width': width, 'stroke-dasharray': dash, opacity: l.kind === 'internet' && !rel.has(l.id) ? 0.55 : 0.95 }),
        svg('path', { d: path, class: 'net-hit', fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 14, onClick: () => pick(l.id) }, svg('title', null, `${(LINK[l.kind] || [l.kind])[0]}: ${nodeName(l.from)} ↔ ${nodeName(l.to)}${l.kind === 'vpn' ? ` · ${l.up}/${l.tunnels.length} tunnels up` : ''}`))));
      if (l.kind === 'vpn' || (l.kind === 'peering' && (l.crossAccount || l.crossProject || l.outside))) {
        const mx = same ? (ca[0] + cb[0]) / 2 + side * (a.w / 2 + 52) : (x1 + x2) / 2, my = (y1 + y2) / 2;
        const t = l.kind === 'vpn' ? `VPN ${l.up}/${l.tunnels.length}${down ? ' ⚠' : ''}` : l.outside ? 'outside' : l.crossAccount ? 'cross-account' : 'cross-project';
        lines.push(svg('g', { opacity: dim(l.id), class: 'net-tag', onClick: () => pick(l.id) }, svg('rect', { x: mx - t.length * 3.4 - 6, y: my - 9, width: t.length * 6.8 + 12, height: 18, rx: 2, fill: 'var(--panel)', stroke: color }),
          svg('text', { x: mx, y: my + 4, 'text-anchor': 'middle', class: 'net-tag-t', fill: color }, t)));
      }
    }
    g.push(...lines);
    // boxes
    for (const n of d.nodes) {
      const p = pos.get(n.id); if (!p) continue;
      const on = f.sel === n.id, hit = match(n);
      const chips = n.kind === 'vpc' && !n.stub ? [`${n.subnets.public}/${n.subnets.total} public`, n.igw ? 'IGW' : null, n.nats ? `NAT×${n.nats}` : null, n.firewall ? 'firewall' : null, n.exposed ? `${n.exposed} exposed` : null].filter(Boolean)
        : n.kind === 'network' && !n.stub ? [`${n.subnets.total} subnets`, n.auto ? 'auto' : null, n.nats ? 'Cloud NAT' : null, n.externalIps ? `${n.externalIps} ext. IP` : null, n.exposed ? `${n.exposed} exposed` : null].filter(Boolean)
        : n.kind === 'peer' ? [n.ip || 'peer'] : n.stub ? [n.yours ? 'yours, not read' : 'not yours', ...(n.cidrs || []).slice(0, 1)] : [];
      const sub = n.kind === 'internet' ? '' : n.kind === 'tgw' ? `transit gateway · ${n.ownerName || n.owner}` : n.stub ? `${n.cloud === 'aws' ? 'account' : 'project'} ${n.ownerName || n.owner}` : (n.cidrs || []).slice(0, 2).join(', ') + ((n.cidrs || []).length > 2 ? ` +${n.cidrs.length - 2}` : '');
      const stroke = on ? 'var(--banana)' : n.kind === 'internet' ? 'var(--faint)' : sevColor(n.worst);
      g.push(svg('g', { class: 'net-node', opacity: hit ? dim(n.id) : 0.15, onClick: () => pick(n.id), tabindex: 0, role: 'button', 'aria-label': `${KIND[n.kind]} ${n.label}`,
        onKeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(n.id); } } },
        svg('rect', { x: p.x, y: p.y, width: p.w, height: p.h, rx: n.kind === 'internet' || n.kind === 'peer' ? 28 : 3, class: `net-box${n.stub ? ' stub' : ''}`, stroke, 'stroke-width': on || (n.worst === 'high') ? 2 : 1.2, 'stroke-dasharray': n.stub ? '4 3' : null }),
        svg('text', { x: p.x + 12, y: p.y + 17, class: 'net-box-eyebrow' }, `${KIND[n.kind]}${n.kind === 'vpc' && n.region ? ` · ${n.region}` : ''}${n.kind === 'network' && n.regions?.length ? ` · ${n.regions.length} region${n.regions.length === 1 ? '' : 's'}` : ''}`),
        svg('text', { x: p.x + 12, y: p.y + 36, class: 'net-box-title' }, n.label.length > 30 ? `${n.label.slice(0, 29)}…` : n.label),
        sub && svg('text', { x: p.x + 12, y: p.y + 53, class: 'net-box-sub' }, sub.length > 40 ? `${sub.slice(0, 39)}…` : sub),
        chips.length ? svg('text', { x: p.x + 12, y: p.y + p.h - 12, class: 'net-box-chips' }, chips.join('  ·  ')) : null,
        n.worst && n.worst !== 'none' && n.findings ? svg('g', null, svg('circle', { cx: p.x + p.w - 14, cy: p.y + 14, r: 9, fill: sevColor(n.worst) }),
          svg('text', { x: p.x + p.w - 14, y: p.y + 18, 'text-anchor': 'middle', class: 'net-badge-t' }, String(n.findings))) : null));
    }
    svgEl.replaceChildren(...g.filter(Boolean));
  }
  const cloudSeg = () => h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'Cloud' }, [['', 'Both clouds'], ['aws', 'AWS'], ['gcp', 'Google Cloud']].map(([v, l]) =>
    h('button', { type: 'button', role: 'radio', 'aria-checked': String(f.cloud === v), onClick: () => { f.cloud = v; toUrl(); draw(); } }, l)));
  function mapView() {
    layout = computeLayout();
    const search = searchBox({ value: f.q, placeholder: 'Find a VPC, network, account, project or range', label: 'Find on the map', onSearch: (v) => { f.q = v.trim(); toUrl(); redrawMap(); } });
    ctx.onLeave(search.cancel);
    const internetBox = h('input', { type: 'checkbox', checked: f.internet });
    internetBox.addEventListener('change', () => { f.internet = internetBox.checked; toUrl(); layout = computeLayout(); fit(); redrawMap(); });
    const out = h('div', null,
      h('div', { class: 'filters' }, search, cloudSeg(), h('label', { class: 'small row', style: 'gap:6px' }, internetBox, 'Lines to the internet'),
        h('span', { style: 'flex:1' }), h('button', { class: 'btn sm', onClick: () => zoom(0.8), 'aria-label': 'Zoom in' }, '+'), h('button', { class: 'btn sm', onClick: () => zoom(1.25), 'aria-label': 'Zoom out' }, '−'), h('button', { class: 'btn sm', onClick: fit }, 'Fit')),
      d.nodes.length ? mapWrap : h('div', { class: 'empty' }, emptyText()));
    requestAnimationFrame(() => { if (d.nodes.length) { fit(); redrawMap(); } });
    return out;
  }
  const emptyText = () => (d.reads.length ? 'Nothing read yet: no VPC or network was found in the accounts and projects read.' : 'Networking has not been read yet. The worker reads every connected AWS account and Google Cloud project within a minute of the extension being turned on; reload in a moment.');

  // ---------------------------------------------------------------- exposure
  function exposureTable(list, withWhere = true) {
    if (!list.length) return h('p', { class: 'small muted' }, 'Nothing with a public address.');
    return h('div', { class: 'scroll' }, h('table', { class: 'inbox-table net-exp' },
      h('thead', null, h('tr', null, ['', 'What', withWhere && 'Where', 'Public address', 'Open to the internet'].filter(Boolean).map((x) => h('th', null, x)))),
      h('tbody', null, list.map((e) => h('tr', { class: 'link', onClick: () => { if (f.tab !== 'map') { f.tab = 'map'; drawTabs(); f.sel = ''; draw(); } pick(nodeOfExposure(e)); } },
        h('td', null, h('span', { class: `badge b-${e.severity === 'none' ? 'neutral' : e.severity}` }, e.severity === 'none' ? 'closed' : e.severity)),
        h('td', null, h('div', { class: 'f-title small' }, e.name), h('div', { class: 'tiny muted' }, e.kind.replace('-', ' '))),
        withWhere && h('td', { class: 'small' }, `${CLOUD[e.cloud]} · ${d.owners.find((o) => o.cloud === e.cloud && o.owner === e.owner)?.name || e.owner}`, h('div', { class: 'tiny muted' }, nodeName(nodeOfExposure(e)))),
        h('td', { class: 'mono tiny' }, e.addresses.join(', ')),
        h('td', { class: 'small' }, e.ports.length ? e.ports.map((p) => h('div', null, h('b', { class: 'mono' }, `${p.proto} ${p.ports}`), h('span', { class: 'tiny muted' }, ` via ${p.via}`))) : h('span', { class: 'muted' }, 'nothing: no rule lets the internet in')))))));
  }
  function exposureView() {
    const list = d.exposures.filter((e) => !f.cloud || e.cloud === f.cloud);
    return h('div', null, h('div', { class: 'filters' }, cloudSeg(), h('span', { class: 'small muted' }, `${list.filter((e) => e.ports.length).length} reachable · ${list.filter((e) => !e.ports.length).length} with a public address but nothing open`)),
      h('p', { class: 'tiny muted', style: 'padding:0 16px' }, 'Instances, interfaces and load balancers with a public address, and what the internet reaches on them through security groups, firewall rules, firewall policies and listeners. High: an admin or database port, or every port.'),
      exposureTable(list));
  }

  // ---------------------------------------------------------------- findings
  let fdata = null, factive = 0;
  async function findingsView() {
    const box = h('div', null, h('div', { class: 'muted small', style: 'padding:16px' }, 'Loading…'));
    const p = new URLSearchParams({ status: f.fstatus }); if (f.fsev) p.set('severity', f.fsev); if (f.cloud) p.set('cloud', f.cloud); if (f.q) p.set('q', f.q);
    fdata = await get(`/network/findings?${p}`); factive = Math.min(factive, Math.max(0, fdata.items.length - 1));
    const sevSel = h('select', { 'aria-label': 'Severity' }, [['', 'Every severity'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['high,medium', 'High and medium']].map(([v, l]) => h('option', { value: v, selected: f.fsev === v }, l)));
    sevSel.addEventListener('change', () => { f.fsev = sevSel.value; toUrl(); draw(); });
    const stSel = h('select', { 'aria-label': 'State' }, [['open', 'Open'], ['resolved', 'Resolved']].map(([v, l]) => h('option', { value: v, selected: f.fstatus === v }, l)));
    stSel.addEventListener('change', () => { f.fstatus = stSel.value; toUrl(); draw(); });
    const search = searchBox({ value: f.q, placeholder: 'Find a finding, group, rule or owner', label: 'Search findings', onSearch: (v) => { f.q = v.trim(); toUrl(); draw(); } });
    ctx.onLeave(search.cancel);
    const detail = h('div', { class: 'inbox-detail' });
    const list = h('div');
    const drawDetail = () => {
      const x = fdata.items[factive];
      if (!x) { detail.replaceChildren(h('div', { class: 'empty' }, 'Nothing here.')); return; }
      const note = h('textarea', { rows: 2, placeholder: 'Why it is expected (required for Expected)', 'aria-label': 'Note' }, x.note || '');
      const decide = async (decision, btn) => busy(btn, async () => {
        await post(`/network-findings/${x.id}/decision`, { decision, note: note.value }); toast(decision === 'expected' ? 'Marked expected' : 'Marked to investigate'); draw();
      });
      const can = x.status === 'open' && !!session.user?.permissions.includes('decide');
      detail.replaceChildren(
        h('div', { class: 'eyebrow' }, `${CLOUD[x.cloud]} · ${x.ownerName}${x.itemType ? ` · ${x.itemType}` : ''}`),
        h('div', { class: 'row' }, h('span', { class: `badge b-${x.severity}` }, x.severity), h('b', null, x.title)),
        h('p', { class: 'small' }, x.detail), x.suggestion && h('p', { class: 'small' }, h('b', null, 'Suggestion: '), x.suggestion),
        kv([['Object', h('span', { class: 'mono tiny' }, `${x.itemName || ''} ${x.nativeId && x.nativeId !== x.itemName ? `(${x.nativeId})` : ''}`)], x.vpc && ['In', h('span', { class: 'mono tiny' }, x.vpc)],
          ['Control', h('a', { href: `#/policy?q=${encodeURIComponent(x.control)}`, class: 'mono tiny' }, x.control)], ['Opened', ago(x.openedAt)], x.resolvedAt && ['Resolved', ago(x.resolvedAt)],
          x.decision && ['Decision', `${x.decision}${x.decidedBy ? ` · ${x.decidedBy}` : ''}${x.note ? `: ${x.note}` : ''}`]]),
        h('div', { class: 'row' }, x.vpc && h('button', { class: 'btn sm', onClick: () => { f.tab = 'map'; drawTabs(); draw(); pick(x.cloud === 'aws' ? `aws:vpc:${x.owner}:${x.vpc}` : `gcp:net:${x.vpc}`); } }, 'Show on the map')),
        can && h('div', { class: 'stack' }, note, h('div', { class: 'row' },
          (() => { const b = h('button', { class: `btn sm${x.decision === 'expected' ? ' primary' : ''}` }, 'Expected'); b.addEventListener('click', () => decide('expected', b)); return b; })(),
          (() => { const b = h('button', { class: `btn sm${x.decision === 'investigate' ? ' primary' : ''}` }, 'Investigate'); b.addEventListener('click', () => decide('investigate', b)); return b; })(),
          x.decision && (() => { const b = h('button', { class: 'btn sm' }, 'Clear decision'); b.addEventListener('click', () => busy(b, async () => { await api('DELETE', `/network-findings/${x.id}/decision`); draw(); })); return b; })())));
    };
    const drawList = () => {
      list.replaceChildren(fdata.items.length ? h('div', { class: 'scroll' }, h('table', { class: 'inbox-table' },
        h('thead', null, h('tr', null, ['Severity', 'Finding', 'Where'].map((x) => h('th', null, x)))),
        h('tbody', null, fdata.items.map((x, i) => h('tr', { class: `link${i === factive ? ' active' : ''}`, onClick: () => { factive = i; drawList(); drawDetail(); } },
          h('td', null, h('span', { class: `badge b-${x.severity}` }, x.severity), x.decision && h('div', { class: 'tiny muted' }, x.decision)),
          h('td', null, h('div', { class: 'f-title small' }, x.title), h('div', { class: 'tiny muted' }, x.control)),
          h('td', { class: 'small' }, `${CLOUD[x.cloud]} · ${x.ownerName}`)))))) : h('div', { class: 'empty' }, f.fstatus === 'open' ? 'No open network findings match.' : 'Nothing resolved matches.'));
    };
    drawList(); drawDetail();
    box.replaceChildren(h('div', { class: 'filters' }, search, cloudSeg(), sevSel, stSel, h('span', { class: 'small muted' }, `${fdata.items.length} finding${fdata.items.length === 1 ? '' : 's'}`)), h('div', { class: 'inbox' }, list, detail));
    return box;
  }

  // ---------------------------------------------------------------- inventory
  async function inventoryView() {
    const p = new URLSearchParams(); if (f.ftype) p.set('type', f.ftype); if (f.cloud) p.set('cloud', f.cloud); if (f.q) p.set('q', f.q);
    const inv = await get(`/network/inventory?${p}`);
    const typeSel = h('select', { 'aria-label': 'Type' }, h('option', { value: '' }, 'Every type'), Object.entries(inv.types).sort((a, b) => (TYPE_LABEL[a[0]] || a[0]).localeCompare(TYPE_LABEL[b[0]] || b[0]))
      .map(([k, n]) => h('option', { value: k, selected: f.ftype === k }, `${TYPE_LABEL[k] || k} (${num(n)})`)));
    typeSel.addEventListener('change', () => { f.ftype = typeSel.value; toUrl(); draw(); });
    const search = searchBox({ value: f.q, placeholder: 'Find by name, ID, address, port…', label: 'Search inventory', onSearch: (v) => { f.q = v.trim(); toUrl(); draw(); } });
    ctx.onLeave(search.cancel);
    const detail = h('div', { class: 'inbox-detail' }, h('div', { class: 'empty' }, 'Pick a row.'));
    const show = (i) => detail.replaceChildren(h('div', { class: 'eyebrow' }, `${CLOUD[i.cloud]} · ${i.owner}${i.region ? ` · ${i.region}` : ''} · ${TYPE_LABEL[i.type] || i.type}`), h('b', null, i.name), h('div', { class: 'mono tiny muted' }, i.id),
      i.vpc && h('div', { class: 'tiny' }, 'In ', h('span', { class: 'mono' }, i.vpc)), h('pre', { class: 'tiny' }, JSON.stringify(i.data, null, 2)));
    return h('div', null, h('div', { class: 'filters' }, search, cloudSeg(), typeSel, h('span', { class: 'small muted' }, `${num(inv.total)} item${inv.total === 1 ? '' : 's'}${inv.total > inv.items.length ? `, first ${inv.items.length} shown` : ''}`)),
      h('div', { class: 'inbox' }, inv.items.length ? h('div', { class: 'scroll' }, h('table', { class: 'inbox-table' }, h('thead', null, h('tr', null, ['Type', 'Name', 'Where'].map((x) => h('th', null, x)))),
        h('tbody', null, inv.items.map((i) => h('tr', { class: 'link', onClick: () => show(i) }, h('td', { class: 'tiny nowrap' }, TYPE_LABEL[i.type] || i.type),
          h('td', null, h('div', { class: 'small' }, i.name), i.name !== i.id && h('div', { class: 'mono tiny muted' }, i.id.length > 60 ? `…${i.id.slice(-58)}` : i.id)),
          h('td', { class: 'tiny' }, `${CLOUD[i.cloud]} · ${i.owner}${i.region ? ` · ${i.region}` : ''}`)))))) : h('div', { class: 'empty' }, 'Nothing matches.'), detail));
  }

  async function draw() {
    toUrl();
    if (f.tab === 'map') { body.replaceChildren(h('div', { class: 'net-body' }, h('section', { class: 'card net-map-card' }, mapView()), panel)); drawPanel(); }
    else if (f.tab === 'exposure') body.replaceChildren(h('section', { class: 'card' }, exposureView()));
    else if (f.tab === 'findings') body.replaceChildren(h('section', { class: 'card' }, await findingsView()));
    else body.replaceChildren(h('section', { class: 'card' }, await inventoryView()));
  }
  drawTabs();
  await draw();
  return h('div', { class: 'stack-lg' }, head, tiles, tabsEl, body);
}
