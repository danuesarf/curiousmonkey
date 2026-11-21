// Watch → Networking (the Networking extension): how VPCs and networks connect, in AWS and Google Cloud and between
// them, what the internet can reach, what is used (VPC flow logs), and what is wrong with it.
//   Space:     the same as a scene (netSpace.js): AWS on the left, Google Cloud on the right, the internet above,
//              lines that carry light while they carry traffic, the last 24 hours to replay.
//   Map:       AWS accounts on the left, Google Cloud projects on the right, each with its VPCs or networks; the
//              internet, transit gateways, Direct Connect gateways, NCC hubs, VPN peers and networks outside your
//              estate in the middle. Lines are peering, transit gateway attachments, VPNs (AWS to Google Cloud matched
//              by tunnel addresses), Direct Connect, Client VPN, PrivateLink, Private Service Connect, Interconnect
//              and the internet. Click anything for what is inside it.
//   Exposure:  every public address and the ports the internet reaches on it, through which rule.
//   Findings:  open ports, default networks, flow logs, outsiders, tunnels down, lines not used; reviewers mark them.
//   Inventory: everything read, searchable.
// Each tab keeps its own search, so a search on one never hides things on another.
import { h, svg, get, post, api, ago, num, toast, busy, syncUrl, tile, searchBox, loadEnvironments, envs, copy, poll, fmtDay } from '../lib.js';
import { session } from '../main.js';
import { networkScene } from './netSpace.js';

const TABS = [['space', 'Space'], ['map', 'Map'], ['exposure', 'Exposure'], ['findings', 'Findings'], ['inventory', 'Inventory']];
const SEV = { high: 0, medium: 1, low: 2, none: 3 };
const RED = 'var(--red)', AMBER = 'var(--amber)';
const sevColor = (s) => (s === 'high' ? RED : s === 'medium' ? AMBER : 'var(--edge)');
const LINK = { peering: ['Peering', 'var(--blue)'], tgw: ['Transit gateway', 'var(--green)'], 'tgw-peering': ['Transit gateway peering', 'var(--green)'], vpn: ['VPN', 'var(--banana)'],
  dx: ['Direct Connect', '#ff9f6b'], 'client-vpn': ['Client VPN', '#7fd1ff'], privatelink: ['PrivateLink', '#d6a2ff'], psc: ['Private Service Connect', '#d6a2ff'], ncc: ['Network Connectivity Center', 'var(--green)'],
  interconnect: ['Interconnect', '#c59bff'], share: ['Shared VPC', '#b9a3ff'], internet: ['Internet', 'var(--faint)'] };
const KIND = { vpc: 'VPC', slice: 'SHARED VPC', network: 'NETWORK', tgw: 'TRANSIT GATEWAY', dxgw: 'DIRECT CONNECT GATEWAY', hub: 'NCC HUB', peer: 'PEER', internet: 'INTERNET' };
const PEER = { dx: 'DIRECT CONNECT', 'client-vpn': 'CLIENT VPN', account: 'ACCOUNT', psc: 'PSC SERVICE' };
const USE = { used: ['used', 'b-green'], unused: ['not used', 'b-neutral'], quiet: ['quiet so far', 'b-neutral'], unknown: ['not known', 'b-neutral'] };
const human = (b) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b >= 1e3 ? `${Math.round(b / 1e3)} kB` : `${b} B`);
// a port a line carried; 0 for TCP or UDP is the rest, folded together as they were read
const portName = (p) => (p.port ? `${p.proto} ${p.port}` : ['tcp', 'udp'].includes(p.proto) ? `${p.proto} other ports` : p.proto);
// a flow log's reading state (src/network/flows.js flowState)
const FLOW = { current: ['read', 'b-green'], 'catching-up': ['reading history', 'b-medium'], waiting: ['not read yet', 'b-neutral'], error: ['cannot be read', 'b-high'], skipped: ['not read', 'b-neutral'] };
const flowSays = (x) => (x.state === 'error' ? x.error : x.state === 'skipped' ? x.note : x.state === 'waiting' ? 'waiting for its first read, within a few minutes'
  : `${x.lastTime ? `newest file ${ago(x.lastTime)}` : 'no files yet'} · ${x.state === 'catching-up' ? `reading history: back to ${fmtDay(x.back)} (${x.historyDays} days)${x.pending ? ` · ${num(x.pending)} new files to read` : ''}` : `${x.historyDays} days read`}${x.note ? ` · ${x.note}` : ''}`);
const flowDest = (x) => `${x.destination === 's3' && x.arn ? x.arn.replace(/^arn:aws[a-z-]*:s3:::/, 's3://') : { 'cloud-watch-logs': 'CloudWatch Logs', 'kinesis-data-firehose': 'Firehose' }[x.destination] || x.destination || ''}${{ ACCEPT: ' · accepted traffic only', REJECT: ' · rejected traffic only' }[x.traffic] || ''}`;
const flowWhere = (x) => `${x.flowLog} → ${flowDest(x)}`;
const CLOUD = { aws: 'AWS', gcp: 'Google Cloud' };
const TYPE_LABEL = { vpc: 'VPCs', subnet: 'Subnets', 'route-table': 'Route tables', igw: 'Internet gateways', eigw: 'Egress-only gateways', nat: 'NAT gateways', sg: 'Security groups', nacl: 'Network ACLs',
  peering: 'VPC peering', tgw: 'Transit gateways', 'tgw-attachment': 'Transit gateway attachments', vpn: 'Site-to-site VPNs', cgw: 'Customer gateways', vgw: 'Virtual private gateways', endpoint: 'VPC endpoints',
  eni: 'Network interfaces', 'flow-log': 'Flow logs', firewall: 'Firewalls / firewall rules', lb: 'Load balancers', network: 'Networks (Google Cloud)', 'firewall-policy': 'Firewall policies', router: 'Cloud Routers',
  route: 'Routes', 'vpn-gateway': 'VPN gateways', 'peer-vpn-gateway': 'Peer VPN gateways', 'vpn-tunnel': 'VPN tunnels', interconnect: 'Interconnect attachments', address: 'External addresses',
  'forwarding-rule': 'Forwarding rules', instance: 'Instances', 'tgw-route-table': 'Transit gateway route tables', 'tgw-peering': 'Transit gateway peering', 'dx-connection': 'Direct Connect connections',
  'dx-vif': 'Direct Connect virtual interfaces', 'dx-gateway': 'Direct Connect gateways', 'dx-association': 'Direct Connect gateway associations', 'client-vpn': 'Client VPN endpoints',
  'endpoint-service': 'PrivateLink services', 'resolver-endpoint': 'Route 53 Resolver endpoints', 'resolver-rule': 'Route 53 Resolver rules', 'prefix-list': 'Prefix lists',
  'ncc-hub': 'NCC hubs', 'ncc-spoke': 'NCC spokes', 'service-attachment': 'PSC service attachments', 'psc-endpoint': 'PSC endpoints', ilb: 'Internal load balancers (Google Cloud)' };

// a security group rule or firewall rule in one line
const awsRule = (r) => `${r.proto === 'all' ? 'all traffic' : `${r.proto} ${r.from == null ? 'all' : r.from === r.to ? r.from : `${r.from}-${r.to}`}`} ← ${[...r.cidrs, ...r.ipv6, ...r.groups.map((g) => (g.account ? `${g.account}/${g.id}` : g.id)), ...r.prefixLists].join(', ') || 'nothing'}`;
const world = (list) => list.some((c) => c === '0.0.0.0/0' || c === '::/0');
const gcpRule = (f) => `${f.action} ${f.rules.map((x) => `${x.proto}${x.ports.length ? `:${x.ports.join(',')}` : ''}`).join(' ')} ${f.direction === 'INGRESS' ? `← ${[...f.sourceRanges, ...f.sourceTags.map((t) => `tag ${t}`), ...f.sourceServiceAccounts].join(', ') || 'any'}` : `→ ${f.destinationRanges.join(', ') || 'any'}`}`;

export async function networkPage(ctx) {
  ctx.setCrumbs('Watch', 'Networking');
  const P = ctx.params;
  // q: the search on Space and the Map (both draw the same things); fq: on Findings; iq: on Inventory
  const f = { tab: TABS.some(([k]) => k === P.get('tab')) ? P.get('tab') : 'space', cloud: ['aws', 'gcp'].includes(P.get('cloud')) ? P.get('cloud') : '', q: P.get('q') || '', sel: P.get('sel') || '',
    fq: P.get('fq') || '', iq: P.get('iq') || '', internet: P.get('internet') !== '0', fsev: P.get('severity') || '', ftype: P.get('type') || '', fstatus: P.get('status') === 'resolved' ? 'resolved' : 'open' };
  // the drawing to go back to from a list ("Show on the map"): the last one open, else the map
  let lastGraph = f.tab === 'space' ? 'space' : 'map';
  await loadEnvironments().catch(() => []);
  const envColor = (id) => envs().find((e) => e.id === id)?.color || 'var(--edge)';
  const envName = (id) => envs().find((e) => e.id === id)?.name || id || '';
  let d = await get('/network');
  const body = h('div');
  const panel = h('aside', { class: 'card net-panel', 'aria-live': 'polite' });
  const toUrl = () => syncUrl({ tab: f.tab === 'space' ? '' : f.tab, cloud: f.cloud, q: f.q, fq: f.fq, iq: f.iq, sel: f.sel, internet: f.internet ? '' : '0', severity: f.fsev, type: f.ftype, status: f.fstatus === 'open' ? '' : f.fstatus });

  // ---------------------------------------------------------------- header
  const reads = () => {
    const ok = d.reads.filter((r) => !r.error), bad = d.reads.filter((r) => r.error), skip = d.reads.filter((r) => r.skipped?.length);
    const fl = d.flowLogs || [], live = fl.filter((x) => x.state === 'current' || x.state === 'catching-up'), behind = fl.filter((x) => x.state === 'catching-up');
    const flCount = (st) => fl.filter((x) => x.state === st).length;
    const newest = live.map((x) => x.lastTime).filter(Boolean).sort().pop();
    const flSum = [flCount('error') && `${flCount('error')} cannot be read`, flCount('skipped') && `${flCount('skipped')} not read`, flCount('waiting') && `${flCount('waiting')} not read yet`,
      behind.length && `${behind.length} reading history`].filter(Boolean).join(' · ') || `each flow log (${fl.length})`;
    const vpcOf = (x) => d.nodes.find((n) => n.id === x.vpcNode)?.label || x.resource;
    // only the worker reads flow logs: say so when none is, or it has not finished a step in 10 minutes
    const step = d.flow?.step, lastStep = step?.last ? Date.now() - new Date(step.last.at).getTime() : null;
    const stopped = !step ? null : !step.workersAlive ? 'No worker is running: new flow log files are not read until one starts.'
      : lastStep == null ? 'Not read yet: a worker reads them within a minute or two.' : lastStep > 10 * 6e4 ? `The worker has not read flow logs for ${ago(step.last.at).replace(' ago', '')}.` : null;
    const last = d.reads.map((r) => r.readAt).sort().pop();
    return h('div', { class: 'small muted net-reads' },
      d.pending && h('div', { class: 'net-pending' }, h('span', { class: 'net-spin', 'aria-hidden': 'true' }), `Reading again, asked ${ago(d.pending)}: this page updates when it is done`),
      d.reads.length ? `Read ${ago(last)} · ${ok.filter((r) => r.cloud === 'aws').length} AWS account${ok.filter((r) => r.cloud === 'aws').length === 1 ? '' : 's'} · ${ok.filter((r) => r.cloud === 'gcp').length} Google Cloud project${ok.filter((r) => r.cloud === 'gcp').length === 1 ? '' : 's'}` : 'Not read yet',
      (bad.length || skip.length) ? h('details', { class: 'net-skips' }, h('summary', null, `${bad.length ? `${bad.length} not read` : ''}${bad.length && skip.length ? ' · ' : ''}${skip.length ? `${skip.length} with reads skipped` : ''}`),
        h('ul', { class: 'tiny' }, [...bad.map((r) => h('li', null, h('b', null, `${r.name}: `), r.error)), ...skip.map((r) => h('li', null, h('b', null, `${r.name}: `), `not allowed to call ${r.skipped.join(', ')}. Add ${r.cloud === 'aws' ? 'them to the scanner role (Accounts → Edit shows the policy)' : 'them to the reader role (Google Cloud setup)'}.`))])) : null,
      h('div', null, fl.length ? `VPC flow logs: ${live.length} read${newest ? `, newest file ${ago(newest)}` : ''}` : 'No VPC flow logs to read',
        fl.length && d.flow ? h('span', { class: 'tiny' }, ` · ${d.flow.lookbackDays} days kept${d.flow.storedBytes != null ? `, ${human(d.flow.storedBytes)}` : ''}`) : null),
      fl.length && stopped ? h('div', { class: 'tiny warn-text' }, stopped) : null,
      fl.length ? h('details', { class: `net-skips net-fl${flCount('error') ? ' bad' : ''}` }, h('summary', null, flSum),
        h('ul', { class: 'tiny' }, fl.map((x) => h('li', null, h('span', { class: `badge ${FLOW[x.state][1]}` }, FLOW[x.state][0]), ' ', h('b', null, vpcOf(x)), h('span', { class: 'muted' }, ` · ${accountName(x.owner)}`),
          h('div', { class: x.state === 'error' ? '' : 'muted' }, flowSays(x)), h('div', { class: 'mono muted' }, flowWhere(x))))),
        step?.last && h('div', { class: 'tiny muted net-fl-by' }, `Read by the worker ${step.last.worker?.hostname || ''}: last step ${ago(step.last.at)}, a step a minute. `,
          session.user?.permissions.includes('ops') ? h('a', { href: '#/operations/workers' }, 'Operations') : null)) : null);
  };
  const readBtn = h('button', { class: 'btn sm' }, 'Read now');
  if (!session.user?.permissions.includes('scan')) readBtn.hidden = true;
  readBtn.addEventListener('click', busy(readBtn, async () => { await post('/network/read'); toast('Networking will be read again within a minute'); d.pending = new Date().toISOString(); drawHead(); watch(); }));
  const readsEl = h('div');
  const drawHead = () => readsEl.replaceChildren(reads());
  const head = h('header', { class: 'head' },
    h('div', null, h('div', { class: 'eyebrow' }, 'WATCH · NETWORKING · EXTENSION'), h('h1', null, 'Networking'),
      h('p', { class: 'small muted', style: 'max-width:820px' }, 'How your VPCs and networks connect, in each cloud and between AWS and Google Cloud: what the internet can reach, which connections are used (VPC flow logs), and what is wrong. Read from VPCs, subnets, routes, gateways, security groups, network ACLs, firewalls, peering, transit gateways, VPNs, Direct Connect, Client VPN, PrivateLink and Private Service Connect.')),
    h('div', { class: 'stack net-head-side' }, readsEl, readBtn));
  let exposed = [];
  const tiles = h('div', { class: 'tiles net-tiles' });
  const openCount = () => d.findings.high + d.findings.medium + d.findings.low;
  function drawTiles() {
    exposed = d.exposures.filter((e) => e.ports.length);
    const other = (l) => l.kind !== 'internet';
    tiles.replaceChildren(
      tile('Reachable from the internet', num(exposed.length), `${exposed.filter((e) => e.severity === 'high').length} on admin, database or all ports`, { bad: exposed.some((e) => e.severity === 'high'), onClick: () => setTab('exposure') }),
      tile('Findings · high', num(d.findings.high), 'click for the list', { bad: d.findings.high > 0, onClick: () => { f.fsev = 'high'; f.fstatus = 'open'; setTab('findings'); } }),
      tile('Findings · medium', num(d.findings.medium), 'click for the list', { onClick: () => { f.fsev = 'medium'; f.fstatus = 'open'; setTab('findings'); } }),
      tile('VPCs and networks', num(d.nodes.filter((n) => (n.kind === 'vpc' || n.kind === 'network') && !n.stub).length), `${d.owners.filter((o) => o.cloud === 'aws').length} accounts · ${d.owners.filter((o) => o.cloud === 'gcp').length} projects`),
      tile('Connections', num(d.links.filter(other).length), `${d.links.filter((l) => l.cross).length} between AWS and Google Cloud`),
      tile('Not used (flow logs)', num(d.links.filter((l) => other(l) && l.usage?.state === 'unused').length),
        `${d.links.filter((l) => other(l) && l.usage?.state === 'used').length} used · ${d.links.filter((l) => other(l) && (!l.usage || l.usage.state === 'unknown')).length} not known`));
  }
  const tabsEl = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Networking' });
  const drawTabs = () => tabsEl.replaceChildren(...TABS.map(([k, l]) => h('button', { role: 'tab', type: 'button', 'aria-selected': String(f.tab === k), onClick: () => setTab(k) },
    l, k === 'findings' && openCount() ? h('span', { class: 'rail-count', style: 'position:static;margin-left:6px', title: 'Open, not marked expected' }, String(openCount())) : null)));
  function setTab(k) { f.tab = k; if (k === 'space' || k === 'map') lastGraph = k; drawTabs(); draw(); }

  // the page again from the server: after a decision, or when a read finishes
  async function reload(fresh) {
    d = fresh || await get('/network');
    drawHead(); drawTiles(); drawTabs();
    if (f.tab === 'space' || f.tab === 'map') await draw(); else drawPanel();
  }
  // while a read is asked for and not done, look every few seconds; when it is done, show what it found
  let stopWatch = null;
  function watch() {
    if (stopWatch || !d.pending) return;
    stopWatch = poll(async () => {
      let x; try { x = await get('/network'); } catch { return; }
      if (x.pending) return;
      stopWatch(); stopWatch = null; toast('Networking read again'); await reload(x);
    }, 8000);
  }
  ctx.onLeave(() => stopWatch?.());

  // ---------------------------------------------------------------- the detail panel
  const sect = (title, ...kids) => h('section', { class: 'net-sect' }, h('h3', { class: 'small' }, title), ...kids);
  const kv = (rows) => h('dl', { class: 'net-kv' }, rows.filter(Boolean).flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  const nodeName = (id) => d.nodes.find((n) => n.id === id)?.label || id;
  // the search on Space and the Map: a name, an ID, an account or project, an address range
  const matchNode = (n, q) => !q || `${n.label} ${n.nativeId || ''} ${n.ownerLabel || ''} ${n.ownerName || ''} ${n.owner || ''} ${(n.cidrs || []).join(' ')}`.toLowerCase().includes(q.toLowerCase());
  const findingRows = (list) => list.length ? h('div', { class: 'stack', style: 'gap:6px' }, list.map((x) => h('button', { class: `net-link-row net-f sev-${x.severity}`, type: 'button', title: 'Open in Findings', onClick: () => openFinding(x.id) },
    h('span', { class: `badge b-${x.severity}` }, x.severity), ' ', h('b', { class: 'small' }, x.title), x.decision && h('span', { class: 'tiny muted' }, ` · ${x.decision}`), h('div', { class: 'tiny muted' }, x.detail))))
    : h('p', { class: 'small muted' }, 'None open.');
  const linkLine = (l) => {
    const [label, color] = LINK[l.kind] || [l.kind, 'var(--muted)'];
    const status = l.kind === 'vpn' ? `${l.up ?? 0}/${l.tunnels?.length || 0} tunnels up` : l.kind === 'internet' ? `out: ${l.egress || '—'}${l.ingress ? ` · ${l.ingress} reachable from it` : ''}` : l.status || '';
    return h('button', { class: 'net-link-row', type: 'button', onClick: () => pick(l.id) }, h('span', { class: 'net-swatch', style: `background:${color}` }), h('b', { class: 'small' }, label), ' ',
      h('span', { class: 'small' }, l.other?.label || nodeName(l.from === f.sel ? l.to : l.from)), h('span', { class: 'tiny muted' }, ` ${status}${l.outside ? ' · outside your estate' : ''}${l.cross ? ' · across clouds' : ''}${l.usage && l.usage.state !== 'unknown' ? ` · ${USE[l.usage.state][0]}${l.usage.bytes ? ` (${human(l.usage.bytes)})` : ''}` : ''}`));
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
      sect('Reachable from the internet first', worst.length ? h('div', { class: 'stack', style: 'gap:6px' }, worst.map((e) => h('button', { class: 'net-link-row', type: 'button', disabled: !e.vpc, onClick: () => select(nodeOfExposure(e)) },
        h('span', { class: `badge b-${e.severity === 'none' ? 'neutral' : e.severity}` }, e.severity === 'none' ? 'closed' : e.severity), ' ', h('b', { class: 'small' }, e.name),
        h('span', { class: 'tiny muted' }, ` ${e.addresses.join(', ')} · ${e.ports.map((p) => p.ports).join(', ')}`)))) : h('p', { class: 'small muted' }, 'Nothing reachable.')),
      sect('Legend', h('div', { class: 'stack', style: 'gap:4px' }, Object.entries(LINK).map(([, [l, c]]) => h('div', { class: 'small' }, h('span', { class: 'net-swatch', style: `background:${c}` }), ' ', l)),
        h('div', { class: 'small' }, h('span', { class: 'net-swatch', style: `background:${RED}` }), ' red border: a high finding; amber: medium. Dashed: down, not routed, or not used (grey, from VPC flow logs).'))));
  }
  const nodeOfExposure = (e) => (e.cloud === 'aws' ? `aws:vpc:${e.owner}:${e.vpc}` : `gcp:net:${e.vpc}`);
  function simpleNode(n) {
    const ls = d.links.filter((l) => l.from === n.id || l.to === n.id);
    return h('div', { class: 'stack', style: 'gap:12px;padding:14px' },
      h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'eyebrow' }, n.kind === 'internet' ? 'THE INTERNET' : n.kind === 'peer' ? PEER[n.sub] || 'VPN OR INTERCONNECT PEER' : `${KIND[n.kind]} · NOT READ`), close),
      h('b', { class: 'name' }, n.label),
      n.kind === 'peer' && h('p', { class: 'small muted' }, n.sub === 'dx' ? `A Direct Connect connection${n.bandwidth ? ` (${n.bandwidth})` : ''}${n.partner ? ` through ${n.partner}` : ''}: a private line from your data centre or office into AWS.${n.state ? ` State: ${n.state}.` : ''}`
        : n.sub === 'client-vpn' ? `People connected with the AWS VPN client, given addresses from ${n.ip}.` : n.sub === 'account' ? `AWS account ${n.owner}${n.yours ? ', yours but not read here' : ', not yours'}: it connects to a PrivateLink service you offer.`
        : `${n.ip ? `${n.ip}: ` : ''}a device outside AWS and Google Cloud as read here (an office, a data centre, another cloud), or a gateway in an account or project no connection reads.`),
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
      d.linkFindings?.[l.id]?.length > 0 && sect(`Findings (${d.linkFindings[l.id].length})`, h('div', { class: 'stack', style: 'gap:6px' }, d.linkFindings[l.id].map((x) => h('button', { class: `net-link-row net-f sev-${x.severity}`, type: 'button',
        onClick: () => openFinding(x.id) }, h('span', { class: `badge b-${x.severity}` }, x.severity), ' ', h('b', { class: 'small' }, x.title))))),
      l.tunnels?.length > 0 && sect('Tunnels', h('table', { class: 'net-table' }, h('thead', null, h('tr', null, ['AWS end', '', 'Google Cloud', ''].map((x) => h('th', null, x)))),
        h('tbody', null, l.tunnels.map((t) => h('tr', null, h('td', { class: 'mono tiny' }, t.aws || t.peer || '—'), h('td', null, t.awsStatus ? h('span', { class: `badge ${t.awsStatus === 'UP' ? 'b-green' : 'b-high'}` }, t.awsStatus === 'UP' ? 'up' : 'down') : ''),
          h('td', { class: 'tiny' }, t.gcp || '—'), h('td', null, t.gcpStatus ? h('span', { class: `badge ${t.gcpStatus === 'ESTABLISHED' ? 'b-green' : 'b-high'}`, title: t.gcpStatus }, t.gcpStatus === 'ESTABLISHED' ? 'up' : 'down') : '')))))),
      l.vpns?.length > 0 && sect('AWS VPN connections', h('ul', { class: 'small' }, l.vpns.map((v) => h('li', null, `${v.name} (${v.id}) to ${v.cgw || 'unknown address'} · ${v.state}`)))),
      l.kind === 'dx' && l.vif && kv([['Virtual interface', `${l.vif} · VLAN ${l.vlan}`], ['BGP', `${l.up}/${l.total} sessions up`], l.prefixes?.length && ['Prefixes', l.prefixes.join(', ')]]),
      l.kind === 'dx' && !l.vif && l.prefixes?.length > 0 && kv([['Allowed prefixes', l.prefixes.join(', ')]]),
      l.kind === 'share' && h('p', { class: 'small muted' }, a?.cloud === 'gcp'
        ? (l.attachedOnly ? `${a?.ownerLabel || a?.owner} is a service project of ${b?.ownerLabel || b?.owner}'s Shared VPC and runs nothing in its networks yet.`
          : `${a?.ownerLabel || a?.owner || 'A service project'} runs its VMs in ${b?.label || 'a network'}, which host project ${b?.ownerLabel || b?.owner || ''} shares with it (Shared VPC): they sit in the host's subnets, under its firewall rules, routes and Cloud NAT. ${plural(l.instances, 'instance')} today.`)
        : `${a?.ownerLabel || a?.owner || 'A member account'} runs its resources in ${b?.label || 'a VPC'}, which ${b?.ownerLabel || b?.owner || 'another account'} owns and shares with it through AWS RAM: they sit in the owner's subnets, behind its route tables, gateways and network ACLs.${l.interfaces != null ? ` ${plural(l.interfaces, 'network interface')} today.` : ''}`),
      l.kind === 'client-vpn' && l.rules?.length > 0 && sect('Who may reach what', h('ul', { class: 'small' }, l.rules.map((r) => h('li', null, `${r.everyone ? 'every user' : `group ${r.group}`} → ${r.cidr}`)))),
      usageSect(l),
      h('div', { class: 'row' }, a && !a.stub && a.kind !== 'internet' && h('button', { class: 'btn sm', onClick: () => pick(a.id) }, `Open ${a.label}`), b && !b.stub && b.kind !== 'internet' && h('button', { class: 'btn sm', onClick: () => pick(b.id) }, `Open ${b.label}`)));
  }
  // what the VPC flow logs say about a line
  function usageSect(l) {
    const u = l.usage; if (!u) return null;
    const [label, cls] = USE[u.state];
    const why = u.state === 'used' ? `${human(u.bytes)} in ${num(u.flows)} accepted flows${u.rejected ? `, ${num(u.rejected)} refused` : ''}, last ${ago(u.last)}`
      : u.state === 'unused' ? `Nothing accepted in ${Math.floor(u.coveredDays)} days of VPC flow logs${u.rejected ? ` (${num(u.rejected)} refused)` : ''}. If nothing needs it, remove it.`
      : u.state === 'quiet' ? `Nothing yet: flow logs read for ${u.coveredDays} days, less than the 3 needed to call it unused.`
      : l.kind === 'privatelink' ? `Only the consumer side can see PrivateLink traffic, and its VPC has no flow logs read.${notKnown([l.from])}` : `No VPC on either side of it has flow logs read (Google Cloud flow logs are not read).${notKnown([l.from, l.to])}`;
    const max = Math.max(1, ...(u.hourly || []).map((b) => b.bytes));
    return sect('Use (VPC flow logs)', h('div', { class: 'row' }, h('span', { class: `badge ${cls}` }, label), h('span', { class: 'small' }, why)),
      u.hourly && h('div', { class: 'net-spark', title: 'Bytes by the hour, the last 24 hours' }, u.hourly.map((b) => h('span', { style: `height:${Math.max(1, Math.round((b.bytes / max) * 26))}px`, class: b.rejected && !b.bytes ? 'rej' : '' }))),
      u.ports.length > 0 && h('div', { class: 'tiny' }, 'Ports: ', u.ports.map((p) => `${portName(p)} (${human(p.bytes)})`).join(', ')));
  }
  // why the flow logs of a line's VPCs say nothing yet: the first of them that has a flow log, in a sentence
  function notKnown(ends) {
    for (const id of ends) {
      const mine = (d.flowLogs || []).filter((x) => x.vpcNode === id); if (!mine.length) continue;
      const name = d.nodes.find((n) => n.id === id)?.label || id;
      const best = ['current', 'catching-up', 'waiting', 'error', 'skipped'].map((st) => mine.find((x) => x.state === st)).find(Boolean);
      const stale = best.lastTime && Date.now() - new Date(best.lastTime).getTime() > 6 * 36e5;
      return ` ${name} has a flow log: ${best.state === 'error' ? `it cannot be read (${best.error})` : best.state === 'skipped' ? best.note : best.state === 'waiting' ? 'it has not been read yet'
        : best.note ? best.note : !best.lastTime ? 'no files were found in its bucket yet' : stale ? `its newest file is from ${ago(best.lastTime)}, older than the 6 hours that count` : 'its first files are still being read'}.`;
    }
    return '';
  }
  // an account or project by the name it goes by here
  const accountName = (id) => d.owners.find((o) => o.owner === id)?.name || d.nodes.find((n) => n.owner === id && n.ownerLabel)?.ownerLabel || id;
  const plural = (k, one, many = `${one}s`) => `${num(k || 0)} ${k === 1 ? one : many}`;
  // what a shared VPC (AWS) or Shared VPC network (Google Cloud) panel says first: whose it is, and what is not known
  function sharedNote(n, x) {
    // AWS accounts go by their names here, Google Cloud projects by their IDs (as on the planes and cards)
    const gcp = n.cloud === 'gcp', host = gcp ? n.vpcOwner : n.vpcOwnerName || n.vpcOwner, who = gcp ? n.owner : accountName(n.owner);
    if (n.kind === 'slice') return h('div', { class: 'net-note' },
      h('p', { class: 'small' }, !gcp ? `${who} runs ${plural(n.interfaces, 'network interface')} in this VPC, which ${host} owns and shares with it (AWS RAM). Its subnets, route tables, gateways and network ACLs are the owner's; the resources below are ${who}'s.`
        : n.attachedOnly ? `${who} is a service project of ${host}'s Shared VPC and runs nothing in its networks yet. It is drawn on ${n.label}, the host's busiest network: it may use any subnet the host grants it.`
          : `${who} runs ${plural(n.instances, 'instance')} in this network, which ${host} shares with it (Shared VPC). Its subnets, firewall rules, routes and Cloud NAT are the host project's; the instances below are ${who}'s.`),
      x.vpcNode && h('button', { class: 'btn sm', onClick: () => select(x.vpcNode) }, gcp ? 'Open the whole network' : 'Open the whole VPC'));
    const notes = [];
    if (n.ownerNotRead) notes.push(gcp ? `The host project (${n.owner}) is not connected, so this network's subnets, firewall rules, routes and Cloud NAT are not known. Connect it to see them.`
      : `The account that owns it (${n.owner}${n.ownerName ? `, ${n.ownerName}` : ''}) is not connected, so its route tables, gateways and network ACLs are not known: which subnets are public, and the way out, are not either. Connect it to see them.`);
    if (n.participantView) notes.push('Shared with an account you can see: only what that account runs here is shown.');
    return notes.length ? h('div', { class: 'net-note' }, notes.map((t) => h('p', { class: 'small' }, t))) : null;
  }
  // who runs what in a shared VPC or a Shared VPC network: the owner (host), each member (service project), and those
  // it is shared with that run nothing yet
  function tenantsSect(list, n) {
    const gcp = n.cloud === 'gcp';
    const how = (t) => (t.owner ? (gcp ? 'host project' : 'owner') : [t.via?.includes('read') && 'read in its account', t.via?.includes('interfaces') && "seen in the owner's subnets",
      t.via?.includes('instances') && 'runs instances here', t.via?.includes('xpn') && "attached to the host's Shared VPC", t.via?.includes('ram') && `RAM share${t.share ? ` ${t.share}` : ''}`].filter(Boolean).join(' · '));
    const cols = gcp ? ['Project', 'Instances', 'External IPs', 'Subnets', 'Exposed'] : ['Account', 'Interfaces', 'Subnets', 'Groups', 'Exposed'];
    const cells = (t) => (gcp ? [t.instances, t.externalIps, (t.subnets || []).length] : [t.interfaces, (t.subnets || []).length, t.securityGroups]);
    return sect(`Who runs what here (${plural(list.length, gcp ? 'project' : 'account')})`, h('table', { class: 'net-table' },
      h('thead', null, h('tr', null, cols.map((y) => h('th', null, y)))),
      h('tbody', null, list.map((t) => {
        // its part of this VPC or network, when it has one drawn
        const slice = d.nodes.find((y) => y.kind === 'slice' && y.owner === t.account && y.nativeId === n.nativeId && y.vpcOwner === n.owner);
        return h('tr', { class: slice ? 'link' : '', onClick: slice ? () => select(slice.id) : null, title: slice ? `Open ${t.name || t.account}'s part` : null },
          h('td', { class: 'small', style: 'width:42%', title: t.hidden ? null : `${gcp && t.name ? `${t.name}. ` : ''}How it is known: ${how(t)}` },
            t.hidden ? h('span', { class: 'muted' }, `${t.name || t.account} (not yours to see)`) : gcp ? h('span', { class: 'mono' }, t.account) : t.name || t.account,
            h('div', { class: 'tiny muted' }, t.hidden ? '' : `${gcp ? '' : `${t.account} · `}${t.owner ? (gcp ? 'host' : 'owner') : t.read ? (gcp ? 'service project' : 'member') : gcp ? 'service project, not connected' : 'not connected'}${t.yours === false ? ' · outside your estate' : ''}`)),
          ...cells(t).map((v) => h('td', { class: 'tiny' }, t.hidden ? '' : num(v || 0))),
          h('td', null, t.exposed ? h('span', { class: 'badge b-medium' }, String(t.exposed)) : h('span', { class: 'tiny muted' }, t.hidden ? '' : '0')));
      }))),
      h('p', { class: 'tiny muted' }, gcp ? "The host project shares its networks with service projects (Shared VPC); each runs its own VMs and load balancers in the host's subnets, under the host's firewall rules and routes."
        : "The owner shares its subnets through AWS RAM; each account runs its own instances, databases and security groups in them, behind the owner's routes."));
  }
  function nodePanel(x) {
    const n = x.node;
    const headRow = h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'eyebrow' }, n.kind === 'slice' ? `SHARED VPC · ${accountName(n.owner).toUpperCase()}'S PART${n.region ? ` · ${n.region}` : ''}`
      : `${KIND[n.kind]} · ${CLOUD[n.cloud] || ''} · ${n.ownerLabel || n.owner}${n.region ? ` · ${n.region}` : ''}`), close);
    const conns = sect(`Connections (${x.links.length})`, x.links.length ? h('div', { class: 'stack', style: 'gap:4px' }, x.links.map(linkLine)) : h('p', { class: 'small muted' }, 'Not connected to anything.'));
    const exp = x.exposures.length ? sect(`Reachable from the internet (${x.exposures.filter((e) => e.ports.length).length})`, exposureTable(x.exposures, true)) : null;
    const finds = sect(`Findings (${x.findings.length})`, findingRows(x.findings));
    if (n.kind === 'vpc' || (n.kind === 'slice' && n.cloud === 'aws')) {
      const pub = x.subnets.filter((s) => s.public).length;
      const shared = (x.tenants || []).length > 1, acct = (id) => (shared ? h('span', { class: 'tiny muted' }, ` · ${accountName(id)}`) : null);
      return h('div', { class: 'stack', style: 'gap:12px;padding:14px' }, headRow,
        h('div', { class: 'row' }, h('b', { class: 'name' }, n.label), n.isDefault && h('span', { class: 'badge b-neutral' }, 'default VPC'),
          shared && h('span', { class: 'badge b-neutral', title: 'Shared through AWS RAM' }, n.kind === 'slice' ? 'your part of a shared VPC' : `shared with ${x.tenants.length - 1} account${x.tenants.length === 2 ? '' : 's'}`)),
        h('div', { class: 'row tiny muted' }, h('span', { class: 'mono' }, n.nativeId), h('button', { class: 'btn sm', onClick: () => copy(n.nativeId) }, 'Copy ID')),
        sharedNote(n, x),
        shared && n.kind !== 'slice' && tenantsSect(x.tenants, n),
        kv([['Address range', n.cidrs.join(', ')], ['Subnets', `${x.subnets.length}: ${pub} public, ${x.subnets.length - pub} private`], ['Internet gateway', n.igw || 'none'],
          ['NAT', n.nats ? `${n.nats}${n.natIps?.length ? ` (${n.natIps.join(', ')})` : ''}` : 'none'], ['Flow logs', x.flowLogs ? 'on' : h('span', { class: 'badge b-medium' }, 'off')],
          ['Network Firewall', x.firewalls.length ? x.firewalls.map((y) => y.name).join(', ') : 'none'], ['Endpoints', x.endpoints.length ? x.endpoints.map((e) => `${e.service.split('.').pop()} (${e.kind.toLowerCase()})`).join(', ') : 'none']]),
        finds, exp, conns,
        sect(`Subnets (${x.subnets.length})`, h('table', { class: 'net-table' }, h('thead', null, h('tr', null, ['Subnet', 'Range', 'Zone', '', 'In it'].map((y) => h('th', null, y)))),
          h('tbody', null, x.subnets.map((s) => h('tr', null, h('td', { class: 'small' }, s.name, h('div', { class: 'mono tiny muted' }, s.id)), h('td', { class: 'mono tiny' }, s.cidr), h('td', { class: 'tiny' }, s.az || ''),
            h('td', null, h('span', { class: `badge ${s.public ? 'b-amber' : 'b-neutral'}` }, s.public ? 'public' : 'private'), s.mapPublicIp && h('div', { class: 'tiny muted' }, 'auto public IP')), h('td', { class: 'tiny' }, num(s.interfaces))))))),
        h('details', null, h('summary', { class: 'small' }, `Security groups (${x.securityGroups.length})`), h('div', { class: 'stack', style: 'gap:8px;margin-top:8px' }, x.securityGroups.map((g) => h('div', { class: 'net-rule-box' },
          h('div', { class: 'row' }, h('b', { class: 'small' }, g.name), h('span', { class: 'mono tiny muted' }, g.id), h('span', { class: 'tiny muted' }, g.used ? `used by ${g.used}` : 'not used'), acct(g.account)),
          g.ingress.length ? h('ul', { class: 'tiny mono' }, g.ingress.map((r) => h('li', { class: world([...r.cidrs, ...r.ipv6]) ? 'net-world' : '' }, `in  ${awsRule(r)}`))) : h('div', { class: 'tiny muted' }, 'no inbound rules'))))),
        h('details', null, h('summary', { class: 'small' }, `Route tables (${x.routeTables.length})`), h('div', { class: 'stack', style: 'gap:8px;margin-top:8px' }, x.routeTables.map((t) => h('div', { class: 'net-rule-box' },
          h('div', { class: 'row' }, h('b', { class: 'small' }, t.name), t.main && h('span', { class: 'badge b-neutral' }, 'main'), h('span', { class: 'tiny muted' }, `${t.subnets.length} subnet${t.subnets.length === 1 ? '' : 's'}`)),
          h('ul', { class: 'tiny mono' }, t.routes.map((r) => h('li', { class: r.state === 'blackhole' ? 'net-world' : '' }, `${r.dest} → ${r.target.type === 'local' ? 'local' : `${r.target.type} ${r.target.id || ''}`}${r.state === 'blackhole' ? ' (blackhole)' : ''}`))))))),
        h('details', null, h('summary', { class: 'small' }, `Network ACLs (${x.nacls.length})`), h('div', { class: 'stack', style: 'gap:8px;margin-top:8px' }, x.nacls.map((a) => h('div', { class: 'net-rule-box' },
          h('div', { class: 'row' }, h('b', { class: 'small' }, a.name), a.isDefault && h('span', { class: 'badge b-neutral' }, 'default')),
          h('ul', { class: 'tiny mono' }, a.entries.filter((e) => !e.egress).map((e) => h('li', { class: e.action === 'allow' && world([e.cidr]) ? 'net-world' : '' }, `in #${e.n} ${e.action} ${e.proto}${e.from != null ? ` ${e.from}-${e.to}` : ''} ← ${e.cidr}`))))))),
        x.flowLogList?.length > 0 && sect('VPC flow logs', h('ul', { class: 'small net-fl-list' }, x.flowLogList.map((fl) => h('li', null, h('span', { class: `badge ${FLOW[fl.state][1]}` }, FLOW[fl.state][0]), ' ',
          h('span', { class: 'mono tiny' }, fl.flowLog), h('div', { class: 'mono tiny muted' }, `→ ${flowDest(fl)}`),
          h('div', { class: `tiny${fl.state === 'error' ? '' : ' muted'}` }, flowSays(fl), fl.files ? ` · ${num(fl.files)} files read in all` : ''))))),
        x.clientVpns?.length > 0 && sect('Client VPN', h('ul', { class: 'small' }, x.clientVpns.map((c) => h('li', null, `${c.name} · users from ${c.cidr} · ${c.auth.join(', ')}${c.split ? ' · split tunnel' : ' · all traffic'}${c.connectionLog ? '' : ' · connections not logged'}`)))),
        x.endpointServices?.length > 0 && sect('PrivateLink services it offers', h('ul', { class: 'small' }, x.endpointServices.map((v) => h('li', null, `${v.name.split('.').pop()} · ${v.connections.length} connected${v.acceptance ? '' : ' · accepted without approval'}`,
          h('div', { class: 'tiny muted' }, v.connections.map((c) => `${c.account} (${c.state})`).join(', ')))))),
        (x.resolver?.endpoints.length || x.resolver?.rules.length) ? sect('DNS (Route 53 Resolver)', h('ul', { class: 'small' }, [...x.resolver.endpoints.map((e) => h('li', null, `${e.direction.toLowerCase()} endpoint ${e.name || e.id}: ${e.ips.map((i) => i.ip).join(', ')}`)),
          ...x.resolver.rules.map((r) => h('li', null, `${r.domain} → ${r.targets.join(', ')} (${r.type.toLowerCase()})`))])) : null,
        x.gateways.length > 0 && sect('Gateways', h('ul', { class: 'small' }, x.gateways.map((g) => h('li', null, `${g.type.toUpperCase()} ${g.name !== g.id ? `${g.name} ` : ''}`, h('span', { class: 'mono tiny muted' }, g.id), g.detail ? ` · ${g.detail}` : '')))),
        x.loadBalancers.length > 0 && sect('Load balancers', h('ul', { class: 'small' }, x.loadBalancers.map((b) => h('li', null, `${b.name} · ${b.kind} · ${b.scheme} · ${b.listeners.map((l) => `${l.proto} ${l.port}`).join(', ')}`)))),
        h('details', null, h('summary', { class: 'small' }, `Network interfaces (${x.interfaces.length})`), h('table', { class: 'net-table' }, h('tbody', null, x.interfaces.map((e) => h('tr', null,
          h('td', { class: 'small' }, e.instance || e.name, acct(e.account), h('div', { class: 'mono tiny muted' }, e.id)), h('td', { class: 'mono tiny' }, e.privateIp || ''), h('td', { class: 'mono tiny' }, e.publicIp || ''), h('td', { class: 'tiny' }, e.groups.join(', '))))))));
    }
    if (n.kind === 'network' || (n.kind === 'slice' && n.cloud === 'gcp')) {
      const shared = (x.tenants || []).length > 1;
      return h('div', { class: 'stack', style: 'gap:12px;padding:14px' }, headRow,
        h('div', { class: 'row' }, h('b', { class: 'name' }, n.label), x.auto && h('span', { class: 'badge b-medium' }, 'auto subnets'),
          shared && h('span', { class: 'badge b-neutral', title: 'Google Cloud Shared VPC' }, n.kind === 'slice' ? 'its part of a Shared VPC network' : `Shared VPC: ${plural(x.tenants.length - 1, 'service project')}`)),
        h('div', { class: 'row tiny muted' }, h('span', { class: 'mono' }, n.nativeId), h('button', { class: 'btn sm', onClick: () => copy(n.nativeId) }, 'Copy')),
        sharedNote(n, x),
        shared && n.kind !== 'slice' && tenantsSect(x.tenants, n),
        kv([['Routing', x.routingMode || '—'], ['Subnets', `${x.subnets.length} in ${[...new Set(x.subnets.map((s) => s.region))].length} region${[...new Set(x.subnets.map((s) => s.region))].length === 1 ? '' : 's'}`],
          ['Cloud NAT', x.routers.flatMap((r) => r.nats.map((m) => `${m.name} (${r.region})`)).join(', ') || 'none'], ['Instances', `${x.instances.length}, ${x.instances.filter((i) => i.interfaces.some((y) => y.natIps.length)).length} with an external address`],
          !shared && n.sharedWith?.length && ['Used by projects', n.sharedWith.join(', ')]]),
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
        h('td', { class: 'small' }, a.resourceType), h('td', { class: 'mono tiny' }, a.resourceId), h('td', { class: 'tiny' }, `account ${a.resourceOwner}`), h('td', { class: 'tiny' }, a.state)))))),
      x.routeTables?.length > 0 && h('details', null, h('summary', { class: 'small' }, `Route tables (${x.routeTables.length})`), h('div', { class: 'stack', style: 'gap:8px;margin-top:8px' }, x.routeTables.map((t) => h('div', { class: 'net-rule-box' },
        h('div', { class: 'row' }, h('b', { class: 'small' }, t.name), t.default && h('span', { class: 'badge b-neutral' }, 'default'), h('span', { class: 'tiny muted' }, `${t.associations.length} associated`)),
        h('ul', { class: 'tiny mono' }, t.routes.map((r) => h('li', { class: r.state === 'blackhole' ? 'net-world' : '' }, `${r.dest} → ${r.attachments.map((a) => `${a.resourceType} ${a.resourceId}`).join(', ') || 'nothing'} (${r.type}${r.state === 'blackhole' ? ', blackhole' : ''})`))))))),
      x.vifs && sect(`Virtual interfaces (${x.vifs.length})`, h('table', { class: 'net-table' }, h('tbody', null, x.vifs.map((v) => h('tr', null, h('td', { class: 'small' }, v.name, h('div', { class: 'tiny muted' }, `${v.kind} · VLAN ${v.vlan}`)),
        h('td', { class: 'tiny' }, v.connection), h('td', null, h('span', { class: `badge ${v.state === 'available' ? 'b-green' : 'b-high'}` }, v.state)), h('td', { class: 'tiny' }, `BGP ${v.bgp.filter((b) => b.status === 'up').length}/${v.bgp.length} up`)))))),
      x.connections && sect('Connections', h('ul', { class: 'small' }, x.connections.map((c) => h('li', null, `${c.name} · ${c.location} · ${c.bandwidth} · ${c.state}${c.partner ? ` · via ${c.partner}` : ''}`)))),
      x.associations && sect('Associated with', h('ul', { class: 'small' }, x.associations.map((a) => h('li', null, `${a.gatewayType === 'transitGateway' ? 'transit gateway' : 'virtual private gateway'} ${a.gateway} (account ${a.gatewayOwner}) · ${a.state}`, a.prefixes.length ? h('div', { class: 'tiny muted' }, `allowed: ${a.prefixes.join(', ')}`) : null)))),
      x.spokes && sect(`Spokes (${x.spokes.length})`, h('ul', { class: 'small' }, x.spokes.map((sp) => h('li', null, `${sp.name} · ${sp.kind}${sp.network ? ` · ${sp.network.split('/').pop()}` : ''} · ${sp.state}`)))),
      finds, conns);
  }
  let scene = null;
  ctx.onLeave(() => scene?.destroy());
  // pick: a click in a drawing (clicking what is selected again lets go of it); select: always selects;
  // show: from a list, back to the drawing last open (Space or the Map) with it selected
  function select(id) { f.sel = id || ''; toUrl(); if (f.tab === 'map') redrawMap(); if (f.tab === 'space') scene?.redraw(); drawPanel(); }
  function pick(id) { select(f.sel === id && id ? '' : id); }
  async function show(id) {
    if (!id) return;
    f.sel = id;
    if (f.tab !== 'space' && f.tab !== 'map') { f.tab = lastGraph; drawTabs(); await draw(); } else select(id);
    body.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }
  const showLabel = () => (lastGraph === 'space' ? 'Show in Space' : 'Show on the map');
  // Esc lets go of what is selected
  const onKey = (e) => { if (e.key === 'Escape' && f.sel && (f.tab === 'space' || f.tab === 'map') && !e.target.closest?.('input, textarea, select')) select(''); };
  document.addEventListener('keydown', onKey);
  ctx.onLeave(() => document.removeEventListener('keydown', onKey));

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
        // its own VPCs or networks, then its part of VPCs other accounts share with it
        const list = d.nodes.filter((n) => n.cloud === cloud && n.owner === o.owner && !n.stub && (n.kind === 'vpc' || n.kind === 'network' || n.kind === 'slice'))
          .sort((a, b) => (a.kind === 'slice' ? 1 : 0) - (b.kind === 'slice' ? 1 : 0) || (a.isDefault ? 1 : 0) - (b.isDefault ? 1 : 0) || (SEV[a.worst] ?? 3) - (SEV[b.worst] ?? 3) || a.label.localeCompare(b.label));
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
    const hubish = (n) => ['tgw', 'dxgw', 'hub'].includes(n.kind);
    const midNodes = d.nodes.filter((n) => shown(n) && (hubish(n) || n.kind === 'peer' || n.stub)).sort((a, b) => (hubish(a) ? 0 : 1) - (hubish(b) ? 0 : 1) || (a.kind === 'peer' ? 1 : 0) - (b.kind === 'peer' ? 1 : 0));
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
    const match = (n) => matchNode(n, f.q);
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
      const unused = l.usage?.state === 'unused' && l.kind !== 'internet';
      const dash = none || unused || (l.kind === 'peering' && l.routed === false) ? '6 5' : l.kind === 'internet' ? '2 4' : null;
      lines.push(svg('g', { opacity: dim(l.id) },
        svg('path', { d: path, fill: 'none', stroke: unused ? '#5f6f68' : color, 'stroke-width': width, 'stroke-dasharray': dash, opacity: l.kind === 'internet' && !rel.has(l.id) ? 0.55 : 0.95 }),
        svg('path', { d: path, class: 'net-hit', fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 14, onClick: () => pick(l.id) }, svg('title', null, `${(LINK[l.kind] || [l.kind])[0]}: ${nodeName(l.from)} ↔ ${nodeName(l.to)}${l.kind === 'vpn' ? ` · ${l.up}/${l.tunnels.length} tunnels up` : ''}`))));
      if (unused || l.kind === 'vpn' || (l.kind === 'peering' && (l.crossAccount || l.crossProject || l.outside))) {
        const mx = same ? (ca[0] + cb[0]) / 2 + side * (a.w / 2 + 52) : (x1 + x2) / 2, my = (y1 + y2) / 2;
        const t = unused ? 'not used' : l.kind === 'vpn' ? `VPN ${l.up}/${l.tunnels.length}${down ? ' ⚠' : ''}` : l.outside ? 'outside' : l.crossAccount ? 'cross-account' : 'cross-project';
        lines.push(svg('g', { opacity: dim(l.id), class: 'net-tag', onClick: () => pick(l.id) }, svg('rect', { x: mx - t.length * 3.4 - 6, y: my - 9, width: t.length * 6.8 + 12, height: 18, rx: 2, fill: 'var(--panel)', stroke: color }),
          svg('text', { x: mx, y: my + 4, 'text-anchor': 'middle', class: 'net-tag-t', fill: color }, t)));
      }
    }
    g.push(...lines);
    // boxes
    for (const n of d.nodes) {
      const p = pos.get(n.id); if (!p) continue;
      const on = f.sel === n.id, hit = match(n);
      const chips = n.kind === 'vpc' && !n.stub ? [`${n.subnets.public}/${n.subnets.total} public`, n.igw ? 'IGW' : null, n.nats ? `NAT×${n.nats}` : null, n.firewall ? 'firewall' : null,
        n.shared ? `shared ×${(n.tenants || []).length - 1}` : null, n.exposed ? `${n.exposed} exposed` : null].filter(Boolean)
        : n.kind === 'slice' ? (n.attachedOnly ? ['attached, nothing running'] : [n.cloud === 'gcp' ? plural(n.instances, 'instance') : plural(n.interfaces, 'interface'), plural(n.subnets?.total, 'subnet'), n.exposed ? `${n.exposed} exposed` : null].filter(Boolean))
        : n.kind === 'network' && !n.stub ? [`${n.subnets.total} subnets`, n.auto ? 'auto' : null, n.nats ? 'Cloud NAT' : null, n.externalIps ? `${n.externalIps} ext. IP` : null, n.exposed ? `${n.exposed} exposed` : null].filter(Boolean)
        : n.kind === 'peer' ? [n.ip || 'peer'] : n.stub ? [n.yours ? 'yours, not read' : 'not yours', ...(n.cidrs || []).slice(0, 1)] : [];
      const sub = n.kind === 'internet' ? '' : n.kind === 'slice' ? `in ${n.vpcOwnerName || n.vpcOwner}'s ${n.cloud === 'gcp' ? 'network' : 'VPC'}` : n.kind === 'tgw' || n.kind === 'dxgw' || n.kind === 'hub' ? `${n.kind === 'hub' ? 'NCC hub' : n.kind === 'dxgw' ? 'Direct Connect gateway' : 'transit gateway'} · ${n.ownerName || n.owner}` : n.stub ? `${n.cloud === 'aws' ? 'account' : 'project'} ${n.ownerName || n.owner}` : (n.cidrs || []).slice(0, 2).join(', ') + ((n.cidrs || []).length > 2 ? ` +${n.cidrs.length - 2}` : '');
      const stroke = on ? 'var(--banana)' : n.kind === 'internet' ? 'var(--faint)' : sevColor(n.worst);
      g.push(svg('g', { class: 'net-node', opacity: hit ? dim(n.id) : 0.15, onClick: () => pick(n.id), tabindex: 0, role: 'button', 'aria-label': `${KIND[n.kind]} ${n.label}`,
        onKeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(n.id); } } },
        svg('rect', { x: p.x, y: p.y, width: p.w, height: p.h, rx: n.kind === 'internet' || n.kind === 'peer' ? 28 : 3, class: `net-box${n.stub ? ' stub' : ''}${n.kind === 'slice' ? ' slice' : ''}`,
          stroke: !on && n.kind === 'slice' && (!n.worst || n.worst === 'none') ? LINK.share[1] : stroke, 'stroke-width': on || (n.worst === 'high') ? 2 : 1.2, 'stroke-dasharray': n.stub || n.kind === 'slice' ? '4 3' : null }),
        svg('text', { x: p.x + 12, y: p.y + 17, class: 'net-box-eyebrow' }, `${n.kind === 'peer' ? PEER[n.sub] || 'PEER' : KIND[n.kind]}${n.kind === 'vpc' && n.region ? ` · ${n.region}` : ''}${n.kind === 'network' && n.regions?.length ? ` · ${n.regions.length} region${n.regions.length === 1 ? '' : 's'}` : ''}`),
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
  // inPanel: the table inside a VPC's own panel, where the rows are already about what is selected
  function exposureTable(list, inPanel = false) {
    if (!list.length) return h('p', { class: 'small muted' }, 'Nothing with a public address.');
    const cols = ['', 'What', !inPanel && 'Where', 'Public address', 'Open to the internet', 'Seen (flow logs)'].filter((x) => x !== false);
    return h('div', { class: 'scroll' }, h('table', { class: 'inbox-table net-exp' },
      h('thead', null, h('tr', null, cols.map((x) => h('th', null, x)))),
      h('tbody', null, list.map((e) => {
        const go = !inPanel && e.vpc;
        return h('tr', { class: go ? 'link' : '', title: go ? showLabel() : null, tabindex: go ? 0 : null, onClick: go ? () => show(nodeOfExposure(e)) : null,
          onKeydown: go ? (ev) => { if (ev.key === 'Enter') show(nodeOfExposure(e)); } : null },
        h('td', null, h('span', { class: `badge b-${e.severity === 'none' ? 'neutral' : e.severity}` }, e.severity === 'none' ? 'closed' : e.severity)),
        h('td', null, h('div', { class: 'f-title small' }, e.name), h('div', { class: 'tiny muted' }, e.kind.replace('-', ' '))),
        !inPanel && h('td', { class: 'small' }, `${CLOUD[e.cloud]} · ${d.owners.find((o) => o.cloud === e.cloud && o.owner === e.owner)?.name || e.owner}`, h('div', { class: 'tiny muted' }, e.vpc ? nodeName(nodeOfExposure(e)) : 'global')),
        h('td', { class: 'mono tiny' }, e.addresses.join(', ')),
        h('td', { class: 'small' }, e.ports.length ? e.ports.map((p) => h('div', null, h('b', { class: 'mono' }, `${p.proto} ${p.ports}`), h('span', { class: 'tiny muted' }, ` via ${p.via}`))) : h('span', { class: 'muted' }, 'nothing: no rule lets the internet in')),
        h('td', { class: 'small' }, e.ports.length && e.ports.some((p) => p.seen) ? e.ports.map((p) => h('div', null, p.seen ? (p.seen.accepted ? `${num(p.seen.accepted)} connections${p.seen.sources ? ` from ${p.seen.sources === 1 ? 'one address' : `${num(p.seen.sources)}+ addresses`}` : ''}` : h('span', { class: 'badge b-neutral' }, 'nobody')) : '—',
          p.seen?.rejected ? h('span', { class: 'tiny muted' }, ` · ${num(p.seen.rejected)} refused`) : null))
          : h('span', { class: 'tiny muted' }, e.cloud === 'gcp' ? 'not read (Google Cloud)' : e.flowDays ? 'nothing in the flow logs' : 'no flow logs read')));
      }))));
  }
  function exposureView() {
    const list = d.exposures.filter((e) => !f.cloud || e.cloud === f.cloud);
    return h('div', null, h('div', { class: 'filters' }, cloudSeg(), h('span', { class: 'small muted' }, `${list.filter((e) => e.ports.length).length} reachable · ${list.filter((e) => !e.ports.length).length} with a public address but nothing open`)),
      h('p', { class: 'tiny muted', style: 'padding:0 16px' }, `Instances, interfaces and load balancers with a public address, and what the internet reaches on them through security groups, firewall rules, firewall policies and listeners. High: an admin or database port, or every port. Click a row: ${showLabel().toLowerCase()}.`),
      exposureTable(list));
  }

  // ---------------------------------------------------------------- findings
  // The filters are drawn once; a search or a filter reloads only the list under them, so typing keeps its place.
  let fdata = null, factive = 0, wantFinding = null;
  function openFinding(id) { wantFinding = id; f.fq = ''; f.fsev = ''; f.fstatus = 'open'; setTab('findings'); }
  function findingsView() {
    const detail = h('div', { class: 'inbox-detail' });
    const list = h('div', null, h('div', { class: 'muted small', style: 'padding:16px' }, 'Loading…'));
    const count = h('span', { class: 'small muted' });
    let seq = 0;
    async function load({ keep = false } = {}) {
      const mine = ++seq, was = keep ? fdata?.items[factive]?.id : null;
      const p = new URLSearchParams({ status: f.fstatus }); if (f.fsev) p.set('severity', f.fsev); if (f.cloud) p.set('cloud', f.cloud); if (f.fq) p.set('q', f.fq);
      let x; try { x = await get(`/network/findings?${p}`); } catch (e) { if (mine === seq) list.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
      if (mine !== seq) return;   // a newer search is under way
      fdata = x;
      const want = wantFinding || was; wantFinding = null;
      const at = want ? fdata.items.findIndex((y) => y.id === want) : -1;
      factive = at >= 0 ? at : keep ? Math.min(factive, Math.max(0, fdata.items.length - 1)) : 0;
      const marked = fdata.items.filter((y) => y.decision === 'expected').length;
      count.textContent = `${num(fdata.items.length)} finding${fdata.items.length === 1 ? '' : 's'}${marked ? ` · ${marked} marked expected` : ''}`;
      drawList(); drawDetail();
    }
    const sevSel = h('select', { 'aria-label': 'Severity' }, [['', 'Every severity'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['high,medium', 'High and medium']].map(([v, l]) => h('option', { value: v, selected: f.fsev === v }, l)));
    sevSel.addEventListener('change', () => { f.fsev = sevSel.value; toUrl(); load(); });
    const stSel = h('select', { 'aria-label': 'State' }, [['open', 'Open'], ['resolved', 'Resolved']].map(([v, l]) => h('option', { value: v, selected: f.fstatus === v }, l)));
    stSel.addEventListener('change', () => { f.fstatus = stSel.value; toUrl(); load(); });
    const search = searchBox({ value: f.fq, placeholder: 'Find a finding, account, project, rule or control', label: 'Search findings', onSearch: (v) => { f.fq = v.trim(); toUrl(); load(); } });
    ctx.onLeave(search.cancel);
    const drawDetail = () => {
      const x = fdata.items[factive];
      if (!x) { detail.replaceChildren(h('div', { class: 'empty' }, 'Nothing here.')); return; }
      const note = h('textarea', { rows: 2, placeholder: 'Why it is expected (required for Expected)', 'aria-label': 'Note' }, x.note || '');
      // a decision changes the counts above and the colours on the drawings, so the page is read again
      const after = async (msg) => { toast(msg); await Promise.all([load({ keep: true }), reload()]); };
      const decideBtn = (decision, label) => {
        const b = h('button', { class: `btn sm${x.decision === decision ? ' primary' : ''}` }, label);
        b.addEventListener('click', busy(b, async () => {
          if (decision === 'expected' && !note.value.trim()) { note.focus(); throw new Error('Say why it is expected first.'); }
          await post(`/network-findings/${x.id}/decision`, { decision, note: note.value });
          await after(decision === 'expected' ? 'Marked expected' : 'Marked to investigate');
        }));
        return b;
      };
      const clearBtn = x.decision && (() => { const b = h('button', { class: 'btn sm' }, 'Clear decision'); b.addEventListener('click', busy(b, async () => { await api('DELETE', `/network-findings/${x.id}/decision`); await after('Decision cleared'); })); return b; })();
      const can = x.status === 'open' && !!session.user?.permissions.includes('decide');
      const target = x.target && (d.nodes.some((n) => n.id === x.target) || d.links.some((l) => l.id === x.target)) ? x.target : null;
      detail.replaceChildren(
        h('div', { class: 'eyebrow' }, `${CLOUD[x.cloud]} · ${x.ownerName}${x.itemType ? ` · ${x.itemType.replace(/-/g, ' ')}` : ''}`),
        h('div', { class: 'row' }, h('span', { class: `badge b-${x.severity}` }, x.severity), h('b', null, x.title)),
        h('p', { class: 'small' }, x.detail), x.suggestion && h('p', { class: 'small' }, h('b', null, 'Suggestion: '), x.suggestion),
        kv([['Object', h('span', { class: 'mono tiny' }, `${x.itemName || ''} ${x.nativeId && x.nativeId !== x.itemName ? `(${x.nativeId})` : ''}`)], x.vpc && ['In', h('span', { class: 'mono tiny' }, x.vpc)],
          ['Control', h('a', { href: `#/policy?q=${encodeURIComponent(x.control)}`, class: 'mono tiny' }, x.control)], ['Opened', ago(x.openedAt)], x.resolvedAt && ['Resolved', ago(x.resolvedAt)],
          x.decision && ['Decision', `${x.decision}${x.decidedBy ? ` · ${x.decidedBy}` : ''}${x.note ? `: ${x.note}` : ''}`]]),
        target && h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => show(target) }, showLabel())),
        can && h('div', { class: 'stack' }, note, h('div', { class: 'row' }, decideBtn('expected', 'Expected'), decideBtn('investigate', 'Investigate'), clearBtn)));
    };
    const drawList = () => {
      list.replaceChildren(fdata.items.length ? h('div', { class: 'scroll' }, h('table', { class: 'inbox-table' },
        h('thead', null, h('tr', null, ['Severity', 'Finding', 'Where'].map((x) => h('th', null, x)))),
        h('tbody', null, fdata.items.map((x, i) => h('tr', { class: `link${i === factive ? ' active' : ''}`, tabindex: 0, onClick: () => { factive = i; drawList(); drawDetail(); },
          onKeydown: (e) => { if (e.key === 'Enter') { factive = i; drawList(); drawDetail(); } } },
          h('td', null, h('span', { class: `badge b-${x.severity}` }, x.severity), x.decision && h('div', { class: 'tiny muted' }, x.decision)),
          h('td', null, h('div', { class: 'f-title small' }, x.title), h('div', { class: 'tiny muted' }, x.control)),
          h('td', { class: 'small' }, CLOUD[x.cloud], h('div', { class: 'tiny muted' }, x.ownerName))))))) : h('div', { class: 'empty' }, f.fstatus === 'open' ? 'No open network findings match.' : 'Nothing resolved matches.'));
    };
    load();
    return h('div', null, h('div', { class: 'filters' }, search, cloudSeg(), sevSel, stSel, count), h('div', { class: 'inbox' }, list, detail));
  }

  // ---------------------------------------------------------------- inventory
  const graphNodeOf = (i) => {
    const id = i.type === 'vpc' ? `aws:vpc:${i.owner}:${i.id}` : i.type === 'network' ? `gcp:net:${i.id}` : i.type === 'tgw' ? `aws:tgw:${i.id}` : i.type === 'dx-gateway' ? `aws:dxgw:${i.id}`
      : i.type === 'ncc-hub' ? `gcp:ncc:${i.id}` : i.vpc ? (i.cloud === 'aws' ? `aws:vpc:${i.owner}:${i.vpc}` : `gcp:net:${i.vpc}`) : null;
    return id && d.nodes.some((n) => n.id === id && !n.stub) ? id : null;
  };
  function inventoryView() {
    const detail = h('div', { class: 'inbox-detail' }, h('div', { class: 'empty' }, 'Pick a row.'));
    const list = h('div', null, h('div', { class: 'muted small', style: 'padding:16px' }, 'Loading…'));
    const count = h('span', { class: 'small muted' });
    const typeSel = h('select', { 'aria-label': 'Type' }, h('option', { value: '' }, 'Every type'));
    typeSel.addEventListener('change', () => { f.ftype = typeSel.value; toUrl(); load(); });
    const search = searchBox({ value: f.iq, placeholder: 'Find by name, ID, address, port…', label: 'Search inventory', onSearch: (v) => { f.iq = v.trim(); toUrl(); load(); } });
    ctx.onLeave(search.cancel);
    let seq = 0, active = null;
    const show1 = (i) => {
      active = `${i.type}|${i.id}`;
      for (const tr of list.querySelectorAll('tr[data-k]')) tr.classList.toggle('active', tr.dataset.k === active);
      const node = graphNodeOf(i);
      detail.replaceChildren(h('div', { class: 'eyebrow' }, `${CLOUD[i.cloud]} · ${i.owner}${i.region ? ` · ${i.region}` : ''} · ${TYPE_LABEL[i.type] || i.type}`), h('b', null, i.name), h('div', { class: 'row tiny muted' }, h('span', { class: 'mono' }, i.id), h('button', { class: 'btn sm', onClick: () => copy(i.id) }, 'Copy ID')),
        i.vpc && h('div', { class: 'tiny' }, 'In ', h('span', { class: 'mono' }, i.vpc)), node && h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => show(node) }, showLabel())),
        h('pre', { class: 'tiny' }, JSON.stringify(i.data, null, 2)));
    };
    async function load() {
      const mine = ++seq;
      const p = new URLSearchParams(); if (f.ftype) p.set('type', f.ftype); if (f.cloud) p.set('cloud', f.cloud); if (f.iq) p.set('q', f.iq);
      let inv; try { inv = await get(`/network/inventory?${p}`); } catch (e) { if (mine === seq) list.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
      if (mine !== seq) return;
      typeSel.replaceChildren(h('option', { value: '' }, 'Every type'), ...Object.entries(inv.types).sort((a, b) => (TYPE_LABEL[a[0]] || a[0]).localeCompare(TYPE_LABEL[b[0]] || b[0]))
        .map(([k, n]) => h('option', { value: k, selected: f.ftype === k }, `${TYPE_LABEL[k] || k} (${num(n)})`)));
      count.textContent = `${num(inv.total)} item${inv.total === 1 ? '' : 's'}${inv.total > inv.items.length ? `, first ${inv.items.length} shown` : ''}`;
      list.replaceChildren(inv.items.length ? h('div', { class: 'scroll' }, h('table', { class: 'inbox-table' }, h('thead', null, h('tr', null, ['Type', 'Name', 'Where'].map((x) => h('th', null, x)))),
        h('tbody', null, inv.items.map((i) => h('tr', { class: `link${active === `${i.type}|${i.id}` ? ' active' : ''}`, 'data-k': `${i.type}|${i.id}`, tabindex: 0, onClick: () => show1(i), onKeydown: (e) => { if (e.key === 'Enter') show1(i); } },
          h('td', { class: 'tiny nowrap' }, TYPE_LABEL[i.type] || i.type),
          h('td', null, h('div', { class: 'small' }, i.name), i.name !== i.id && h('div', { class: 'mono tiny muted' }, i.id.length > 60 ? `…${i.id.slice(-58)}` : i.id)),
          h('td', { class: 'tiny' }, `${CLOUD[i.cloud]} · ${i.owner}${i.region ? ` · ${i.region}` : ''}`)))))) : h('div', { class: 'empty' }, 'Nothing matches.'));
    }
    load();
    return h('div', null, h('div', { class: 'filters' }, search, cloudSeg(), typeSel, count), h('div', { class: 'inbox' }, list, detail));
  }

  // the tab's body; a newer draw wins over one still waiting
  let drawSeq = 0;
  async function draw() {
    const mine = ++drawSeq;
    toUrl();
    scene?.destroy(); scene = null;
    let el;
    if (f.tab === 'space') {
      if (!d.nodes.length) el = h('section', { class: 'card' }, h('div', { class: 'empty' }, emptyText()));
      else { scene = spaceView(); el = h('div', { class: 'net-body' }, h('section', { class: 'card net-map-card' }, scene.el), panel); }
    } else if (f.tab === 'map') el = h('div', { class: 'net-body' }, h('section', { class: 'card net-map-card' }, mapView()), panel);
    else if (f.tab === 'exposure') el = h('section', { class: 'card' }, exposureView());
    else if (f.tab === 'findings') el = h('section', { class: 'card' }, findingsView());
    else el = h('section', { class: 'card' }, inventoryView());
    if (mine !== drawSeq) return;
    body.replaceChildren(el);
    if (f.tab === 'space' || f.tab === 'map') drawPanel();
  }
  // Space: the scene, with the same search as the map (what does not match is dimmed)
  function spaceView() {
    const search = searchBox({ value: f.q, placeholder: 'Find a VPC, network, account or range', label: 'Find in Space', onSearch: (v) => { f.q = v.trim(); toUrl(); scene?.redraw(); } });
    search.classList.add('ns-find');
    ctx.onLeave(search.cancel);
    return networkScene(d, { pick, sel: () => f.sel, envColor, tools: [search], match: (n) => matchNode(n, f.q),
      internet: () => f.internet, onInternet: (v) => { f.internet = v; toUrl(); } });
  }
  drawHead(); drawTiles(); drawTabs();
  await draw();
  watch();
  return h('div', { class: 'stack-lg' }, head, tiles, tabsEl, body);
}
