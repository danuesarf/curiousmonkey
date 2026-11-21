// The Networking extension: turning it on and off, reading AWS and Google Cloud networking (demo), the analyzer's
// findings, exposure and map (AWS to Google Cloud VPN matched by tunnel addresses), and the page's API.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
// the database URL has to be set before anything that opens the pool is imported
process.env.DATABASE_URL = 'postgres://cm:cm@127.0.0.1:54391/cm';
const { analyzeNetwork, classifyPorts, overlaps, range4 } = await import('../src/network/analyze.js');
const { normalizeAwsRegion } = await import('../src/network/awsReader.js');
const { normalizeGcpProject } = await import('../src/network/gcpReader.js');
const { demoAwsNetwork, demoGcpNormalized } = await import('../src/network/demo.js');
const { scannerPolicy } = await import('../src/onboarding.js');
const { gcpSnippets } = await import('../src/gcp/onboarding.js');
const { flowRouter, aggregate, parseFlowText, s3Dest, fileTime, dayPrefix } = await import('../src/network/flows.js');
const { demoFlowKeys, demoFlowFile } = await import('../src/network/demo.js');
const zlib = await import('node:zlib');
const PROD = '111111111111', DATA = '222222222222';
const PROJECTS = ['acme-shared-ci', 'acme-data-stg', 'acme-payments-prod'];
const demoItems = () => [
  ...[PROD, DATA].flatMap((a) => demoAwsNetwork(a, 'us-east-1').items.map((i) => ({ ...i, cloud: 'aws', owner: a }))),
  ...PROJECTS.flatMap((p) => demoGcpNormalized(p).map((i) => ({ ...i, cloud: 'gcp', owner: p }))),
];
const estate = { awsAccounts: new Map([[PROD, { name: 'payments-prod' }], [DATA, { name: 'data-platform-stg' }]]), gcpProjects: new Map(PROJECTS.map((p) => [p, {}])) };
const sev = (r, control) => r.findings.filter((f) => f.control === control).map((f) => `${f.itemName}:${f.severity}`).sort();

// ---------------------------------------------------------------- no database
test('ports and ranges: admin, database, every port; CIDR overlap', () => {
  assert.deepEqual(classifyPorts([[22, 22]]).admin, [22]);
  assert.deepEqual(classifyPorts([[3300, 3400]]).admin, [3389]); assert.deepEqual(classifyPorts([[3300, 3400]]).data, [3306]);
  assert.equal(classifyPorts(null).all, true);
  assert.equal(classifyPorts([[1000, 5000]]).wide, true);
  assert.equal(classifyPorts([[443, 443]]).admin.length + classifyPorts([[443, 443]]).data.length, 0);
  assert.deepEqual(range4('10.0.0.0/8'), [167772160, 184549375]);
  assert.equal(overlaps('10.10.0.0/16', '10.10.4.0/24'), true); assert.equal(overlaps('10.10.0.0/16', '10.20.0.0/16'), false);
});

test('normalising: security group rules, route targets, peering sides; Google Cloud firewall rules and network paths', () => {
  const it = normalizeAwsRegion('us-east-1', {
    sgs: [{ GroupId: 'sg-1', GroupName: 'web', VpcId: 'vpc-1', IpPermissions: [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }, { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, UserIdGroupPairs: [{ GroupId: 'sg-2', UserId: '1' }] }] }],
    routeTables: [{ RouteTableId: 'rtb-1', VpcId: 'vpc-1', Associations: [{ Main: true }], Routes: [{ DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'igw-1' }, { DestinationCidrBlock: '10.9.0.0/16', TransitGatewayId: 'tgw-1' }] }],
  });
  const sg = it.find((x) => x.type === 'sg');
  assert.deepEqual([sg.data.ingress[0].proto, sg.data.ingress[0].cidrs, sg.data.ingress[1].groups[0].id], ['all', ['0.0.0.0/0'], 'sg-2']);
  assert.deepEqual(it.find((x) => x.type === 'route-table').data.routes.map((r) => r.target.type), ['igw', 'tgw']);
  const g = normalizeGcpProject('p1', { firewalls: [{ name: 'ssh', network: 'https://www.googleapis.com/compute/v1/projects/p1/global/networks/n1', direction: 'INGRESS', allowed: [{ IPProtocol: 'tcp', ports: ['22'] }], sourceRanges: ['0.0.0.0/0'] }] });
  assert.deepEqual([g[0].vpc, g[0].data.action, g[0].data.rules[0].ports], ['projects/p1/global/networks/n1', 'allow', ['22']]);
});

test('findings: open ports by who uses them, default networks, flow logs, outsiders, tunnels down', () => {
  const r = analyzeNetwork(demoItems(), estate);
  // SSH on a bastion with a public address is high; RDP on a group nothing uses is low; Redis on a cache with no public address is medium
  assert.deepEqual(sev(r, 'net.sg-admin-open'), ['bastion:high', 'legacy-rdp:low']);
  assert.deepEqual(sev(r, 'net.sg-data-open'), ['redis-cache:medium']);
  assert.ok(sev(r, 'net.sg-unused').includes('legacy-rdp:low'));
  assert.deepEqual(sev(r, 'net.peering-external'), ['vendor-analytics:medium']);
  assert.match(r.findings.find((f) => f.control === 'net.peering-external').title, /999999999999/);
  assert.deepEqual(sev(r, 'net.flow-logs-off'), ['data-platform:medium'], 'prod-core has flow logs; empty default VPCs are not counted');
  assert.deepEqual(sev(r, 'net.vpn-down'), ['gcp-ha-1:low', 'office-hq:medium']);
  // Google Cloud: SSH open on an instance with an external address is high; Redis open to instances with none is medium
  assert.deepEqual(sev(r, 'net.gcp-fw-admin-open'), ['allow-ssh-anywhere:high', 'default-allow-rdp:high', 'default-allow-ssh:high']);
  assert.deepEqual(sev(r, 'net.gcp-fw-data-open'), ['allow-redis-anywhere:medium']);
  assert.ok(!r.findings.some((f) => f.itemName === 'allow-iap-ssh'), 'SSH from Identity-Aware Proxy only is fine');
  assert.deepEqual(sev(r, 'net.gcp-default-network'), ['default:medium']);
  assert.deepEqual(sev(r, 'net.gcp-peering-external'), ['data-vpc:medium']);
  assert.deepEqual(sev(r, 'net.gcp-vpn-down'), ['aws-tunnel-3:low']);
  // a control turned off in the workspace's policy makes no finding
  const off = analyzeNetwork(demoItems(), estate, { over: new Map([['net.sg-admin-open', { enabled: false, severity: null }]]), rules: [], sig: '' });
  assert.equal(sev(off, 'net.sg-admin-open').length, 0);
  // the vendor is yours once its account is in the organisation
  const org = analyzeNetwork(demoItems(), { ...estate, orgAccounts: new Map([['999999999999', 'analytics']]) });
  assert.equal(sev(org, 'net.peering-external').length, 0);
});

test('exposure: public addresses and what the internet reaches on them', () => {
  const r = analyzeNetwork(demoItems(), estate);
  const by = Object.fromEntries(r.exposures.map((e) => [e.name, e]));
  assert.equal(by['bastion (i-0a10000000bastion)'].severity, 'high');
  assert.deepEqual(by['bastion (i-0a10000000bastion)'].ports.map((p) => p.ports), ['22']);
  assert.deepEqual(by['payments-web'].ports.map((p) => p.ports).sort(), ['443', '80']);
  assert.equal(by['payments-web'].severity, 'low');
  assert.deepEqual(by['payments-api-1'].ports.map((p) => p.ports).sort(), ['22', '3389'], 'the load balancer health check ranges are not the internet');
  assert.ok(!r.exposures.some((e) => /NAT/.test(e.name)), 'a NAT gateway takes nothing in');
});

test('the map: peering, transit gateway, AWS to Google Cloud VPN matched by addresses, an office peer, outsiders', () => {
  const { nodes, links } = analyzeNetwork(demoItems(), estate).graph;
  const L = (kind, a, b) => links.find((l) => l.kind === kind && [l.from, l.to].sort().join('|') === [a, b].sort().join('|'));
  const prod = `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`, data = `aws:vpc:${DATA}:vpc-0b2b2c3d4e5f60020`, tgw = 'aws:tgw:tgw-0a1b2c3d4e5f60001';
  const transit = 'gcp:net:projects/acme-shared-ci/global/networks/transit';
  assert.equal(L('peering', prod, data).crossAccount, true);
  assert.equal(L('peering', prod, data).routed, true);
  assert.ok(L('tgw', prod, tgw) && L('tgw', data, tgw));
  const vpn = L('vpn', tgw, transit);
  assert.ok(vpn, 'the two AWS VPN connections land on the Google Cloud HA VPN gateway');
  assert.equal(vpn.cross, true); assert.equal(vpn.tunnels.length, 4); assert.equal(vpn.up, 3);
  assert.deepEqual(vpn.vpns.map((v) => v.name).sort(), ['gcp-ha-0', 'gcp-ha-1']);
  assert.equal(L('vpn', tgw, 'peer:198.51.100.200').up, 0);
  assert.equal(L('peering', transit, 'gcp:net:projects/acme-data-stg/global/networks/data-vpc').crossProject, true);
  const outsider = nodes.find((n) => n.id === `aws:vpc:999999999999:vpc-0c9c9c9c9c9c90099`);
  assert.equal(outsider.stub, true); assert.equal(outsider.yours, false);
  assert.equal(nodes.find((n) => n.id === 'gcp:net:projects/partner-data-net-4821/global/networks/partner-vpc').yours, false);
  assert.equal(L('internet', prod, 'internet').ingress, 2, 'the bastion and the load balancer');
  assert.ok(!links.some((l) => l.kind === 'internet' && l.from === transit), 'the transit network has no way out');
  assert.equal(nodes.find((n) => n.id === prod).worst, 'high');
});

test('onboarding: the scanner policy and the Google Cloud role get the networking reads only when asked', () => {
  const st = (p) => p.Statement.find((s) => s.Sid === 'ReadNetworking');
  assert.equal(st(scannerPolicy({})), undefined);
  assert.ok(st(scannerPolicy({ network: true })).Action.includes('ec2:DescribeSecurityGroups'));
  assert.ok(!gcpSnippets({ scopeType: 'organization', scopeId: '1' }).permissions.includes('compute.firewalls.list'));
  const g = gcpSnippets({ scopeType: 'organization', scopeId: '1', network: true });
  assert.ok(g.permissions.includes('compute.firewalls.list'));
  assert.ok(g.steps.some((s) => /add-permissions=compute\.networks\.list/.test(s.code)));
});

test('Direct Connect, Client VPN, PrivateLink, Network Connectivity Center and Private Service Connect on the map, with their findings', () => {
  const r = analyzeNetwork(demoItems(), estate), L = (kind) => r.graph.links.filter((l) => l.kind === kind);
  assert.deepEqual(L('dx').map((l) => [l.from, l.to].sort().join(' ↔ ')).sort(), ['aws:dxgw:dxgw-0a10main ↔ aws:tgw:tgw-0a1b2c3d4e5f60001', 'aws:dxgw:dxgw-0a10main ↔ dx:dxcon-0a10jk1']);
  assert.equal(L('dx').find((l) => l.vif === 'transit').up, 2);
  assert.equal(L('client-vpn').length, 1);
  assert.deepEqual(L('privatelink').map((l) => l.outside).sort(), [false, true], 'data-platform is yours, the vendor is not');
  assert.equal(L('ncc').length, 2);
  assert.ok(L('psc').some((l) => l.to.includes('acme-payments-prod') || l.from.includes('acme-payments-prod')));
  assert.deepEqual(['net.dx-single', 'net.tgw-blackhole', 'net.client-vpn-wide', 'net.client-vpn-no-log', 'net.privatelink-external', 'net.gcp-psc-external'].map((c) => sev(r, c).length), [1, 1, 1, 1, 1, 1]);
});

test('flow logs: file names, headers, and each record on the line it travelled (route tables, transit gateway routes, paths across the clouds)', () => {
  assert.deepEqual(s3Dest('arn:aws:s3:::logs-bucket/vpc/prod'), { bucket: 'logs-bucket', prefix: 'vpc/prod' });
  assert.equal(dayPrefix({ prefix: 'p', account: PROD, region: 'us-east-1' }, Date.UTC(2026, 0, 5)), `p/AWSLogs/${PROD}/vpcflowlogs/us-east-1/2026/01/05/`);
  assert.equal(fileTime(`x/${PROD}_vpcflowlogs_us-east-1_fl-1_20260105T1005Z_abc.log.gz`), Date.UTC(2026, 0, 5, 10, 5));
  const custom = [...parseFlowText('interface-id srcaddr dstaddr srcport dstport protocol bytes packets start action log-status\neni-1 10.0.0.1 10.0.0.2 1 22 6 100 1 0 ACCEPT OK\neni-1 - - - - - - - 0 - NODATA\n')];
  assert.deepEqual([custom.length, custom[0].dstport, custom[0]['interface-id']], [1, '22', 'eni-1']);

  const items = demoItems(), g = analyzeNetwork(items, estate).graph, route = flowRouter(items, g);
  const agg = { links: new Map(), exposure: new Map() };
  const keys = demoFlowKeys({ bucket: 'acme-flow-logs', prefix: dayPrefix({ prefix: '', account: PROD, region: 'us-east-1' }, Date.now() - 864e5) });
  assert.equal(keys.length, 24);
  for (const k of keys) aggregate([...parseFlowText(zlib.gunzipSync(demoFlowFile(k.key)).toString())], route, agg);
  const used = new Set([...agg.links.values()].map((x) => x.link.split(':')[0] + ':' + x.link.split('|').map((y) => y.split(':').pop()).join('|')));
  const kinds = [...new Set([...agg.links.values()].map((x) => x.link.split(':')[0]))].sort();
  assert.deepEqual(kinds, ['client-vpn', 'dx', 'internet', 'peering', 'tgw', 'vpn']);
  assert.ok(![...used].some((x) => x.includes('vpc-0c9c9c9c9c9c90099')), 'nothing on the vendor peering');
  assert.ok(![...agg.links.values()].some((x) => x.link.includes('198.51.100.200')), 'nothing on the office VPN');
  const ssh = [...agg.exposure.values()].filter((x) => x.target === 'eni-0a100000000bastion');
  assert.deepEqual([...new Set(ssh.map((x) => `${x.port}:${x.action}`))].sort(), ['22:ACCEPT', '23:REJECT', '3389:REJECT']);
  assert.ok([...agg.exposure.values()].some((x) => x.target.endsWith('payments-web/0a1b2c3d4e5f6000') && x.port === 443), 'the load balancer, not its interface');
  // the S3 call through the gateway endpoint is not internet traffic
  assert.ok(![...agg.links.values()].some((x) => x.link.startsWith('internet') && x.port === 443 && x.bytes === 40000));
});

test('the scanner policy reads flow log files and nothing else', () => {
  const p = scannerPolicy({ network: true }), st = (sid) => p.Statement.find((x) => x.Sid === sid);
  assert.deepEqual(st('ReadFlowLogFiles').Resource, ['arn:aws:s3:::*/AWSLogs/*/vpcflowlogs/*', 'arn:aws:s3:::*/AWSLogs/aws-account-id=*/aws-service=vpcflowlogs/*']);
  assert.deepEqual(st('NeverReadOtherObjects').NotResource, st('ReadFlowLogFiles').Resource);
  assert.ok(st('NeverDecryptOtherData').Condition.StringNotLike);
  const both = scannerPolicy({ network: true, s3: { bucket: 'trail', prefix: '' } });
  assert.equal(both.Statement.find((x) => x.Sid === 'NeverReadOtherObjects').NotResource.length, 3);
  assert.deepEqual(Object.keys(both.Statement.find((x) => x.Sid === 'NeverDecryptOtherData').Condition).sort(), ['Null', 'StringNotLike']);
  assert.ok(!scannerPolicy({}).Statement.some((x) => x.Sid === 'ReadFlowLogFiles'));
});

// ---------------------------------------------------------------- with the database
let pg, db, ext, sync, api, gscan;
const owner = { id: null, scope_accounts: null };
before(async () => {
  pg = await startPg(54391);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  ext = await import('../src/extensions.js'); sync = await import('../src/network/sync.js'); api = await import('../src/network/api.js'); gscan = await import('../src/gcp/scan.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','x')`);
  for (const [id, name] of [[PROD, 'payments-prod'], [DATA, 'data-platform-stg']]) {
    await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ($1,$2,'production','arn:aws:iam::${id}:role/cm','{us-east-1}','connected')`, [id, name]);
  }
  const conn = (await db.query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode, wif, environment, status) VALUES ('acme.example','organization','100000000001','wif','{}','shared','connected') RETURNING *`)).rows[0];
  await gscan.scanGcpConnection(conn);
});
after(async () => { await db?.closePool(); await pg?.stop(); });

test('off by default: nothing is read; turning it on reads every account and project and files findings', async () => {
  assert.deepEqual([...await ext.enabledExtensions({ fresh: true })], []);
  assert.equal(await sync.networkTick(), null);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM net_items')).rows[0].n, 0);

  assert.equal(await ext.setExtension('networking', true, null), true);
  assert.equal(await ext.setExtension('networking', true, null), false, 'no change, nothing to log');
  await sync.requestNetworkRead();
  await ext.enabledExtensions({ fresh: true });
  const r = await sync.networkTick();
  assert.deepEqual([r.aws, r.gcp, r.errors], [2, 3, 0]);
  assert.ok(r.findings > 10);
  // a second tick has nothing due
  assert.equal(await sync.networkTick(), null);
  const reads = (await db.query(`SELECT cloud, owner, error FROM net_reads ORDER BY cloud, owner`)).rows;
  assert.deepEqual(reads.map((x) => `${x.cloud}:${x.owner}:${x.error}`), ['aws:111111111111:null', 'aws:222222222222:null', 'gcp:acme-data-stg:null', 'gcp:acme-payments-prod:null', 'gcp:acme-shared-ci:null']);
  const f = (await db.query(`SELECT control, severity, item_name FROM net_findings WHERE status = 'open' AND control = 'net.sg-admin-open' ORDER BY item_name`)).rows;
  assert.deepEqual(f.map((x) => `${x.item_name}:${x.severity}`), ['bastion:high', 'legacy-rdp:low']);
});

test('the page: overview, a VPC and a network in detail, findings with decisions, the inventory, scope', async () => {
  const o = await api.networkOverview(owner);
  assert.ok(o.nodes.some((n) => n.label === 'prod-core' && n.environment === 'production'));
  assert.ok(o.links.some((l) => l.kind === 'vpn' && l.cross && l.up === 3));
  assert.ok(o.exposures[0].severity === 'high');
  assert.ok(o.findings.high >= 4);
  const vpc = await api.networkDetail(owner, `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`);
  assert.equal(vpc.subnets.filter((s) => s.public).length, 2);
  assert.ok(vpc.securityGroups.some((g) => g.name === 'bastion' && g.used === 1));
  assert.equal(vpc.flowLogs, true);
  assert.ok(vpc.links.some((l) => l.kind === 'peering' && l.other.label === 'data-platform'));
  const net = await api.networkDetail(owner, 'gcp:net:projects/acme-shared-ci/global/networks/ci');
  assert.ok(net.firewallRules.some((x) => x.name === 'allow-ssh-anywhere'));
  assert.equal(net.instances[0].name, 'ci-runner-1');
  await assert.rejects(api.networkDetail(owner, 'aws:vpc:000:nope'), /Not found/);

  const list = await api.networkFindings(owner, { severity: 'high' });
  const bastion = list.items.find((x) => x.itemName === 'bastion');
  await assert.rejects(api.decideNetFinding(owner, bastion.id, { decision: 'expected', note: '' }), /why/);
  await api.decideNetFinding({ ...owner, id: null }, bastion.id, { decision: 'expected', note: 'IP-restricted at the edge' });
  assert.equal((await api.networkFindings(owner, { severity: 'high' })).items.find((x) => x.id === bastion.id).decision, 'expected');
  await api.undecideNetFinding(owner, bastion.id);

  const inv = await api.networkInventory(owner, { type: 'sg' });
  assert.ok(inv.items.every((i) => i.type === 'sg') && inv.types.vpc >= 4);
  assert.ok((await api.networkInventory(owner, { q: '198.51.100.77' })).items.some((i) => i.name === 'ci-runner-1'));

  // a member limited to one AWS account: that account's networks, nothing from Google Cloud
  const acct = (await db.query(`SELECT id FROM cloud_accounts WHERE account_id = $1`, [DATA])).rows[0].id;
  const scoped = { id: null, scope_accounts: [acct] };
  const so = await api.networkOverview(scoped);
  assert.ok(so.nodes.filter((n) => !n.stub && n.cloud).every((n) => n.cloud === 'aws' && n.owner === DATA), 'only its own VPCs in full');
  const far = so.nodes.find((n) => n.id === `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`);
  assert.deepEqual([far.hidden, far.cidrs, far.worst], [true, [], 'none'], 'the other end of its peering: a name, nothing inside');
  assert.ok(!so.nodes.some((n) => n.cloud === 'gcp'));
  assert.ok(so.exposures.every((e) => e.cloud === 'aws' && e.owner === DATA));
  assert.ok((await api.networkFindings(scoped, {})).items.every((x) => x.cloud === 'aws' && x.owner === DATA));
  await assert.rejects(api.networkDetail(scoped, 'gcp:net:projects/acme-shared-ci/global/networks/ci'), /Not found/);
});

test('flow logs from S3: read once, a budget at a time; lines used, not used, not known; ports nobody uses', async () => {
  const flows = await import('../src/network/flows.js');
  const r = await flows.flowTick();
  assert.ok(r.files >= 7 * 24 && r.errors === 0, JSON.stringify(r));
  assert.equal((await flows.flowTick())?.files || 0, 0, 'every file is read once');
  const reads = (await db.query('SELECT * FROM net_flow_reads')).rows;
  assert.equal(reads.find((x) => x.flow_log === 'fl-0a10000000000001').bucket, 'acme-flow-logs');
  await sync.analyzeAndFile();
  (await import('../src/cache.js')).clearCache();
  const o = await api.networkOverview(owner);
  const L = (kind, has) => o.links.find((l) => l.kind === kind && (l.from.includes(has) || l.to.includes(has)));
  assert.equal(L('peering', 'vpc-0b2b2c3d4e5f60020').usage.state, 'used');
  assert.equal(L('peering', 'vpc-0c9c9c9c9c9c90099').usage.state, 'unused');
  assert.equal(L('vpn', 'transit').usage.state, 'used');
  assert.equal(L('vpn', '198.51.100.200').usage.state, 'unused', 'covered through the transit gateway');
  assert.equal(L('dx', 'dxcon').usage.state, 'used');
  assert.equal(L('peering', 'acme-data-stg').usage.state, 'unknown', 'only Google Cloud sees it');
  assert.equal(L('privatelink', 'vpc-0b2b2c3d4e5f60020').usage.state, 'unknown', 'only the consumer side can see PrivateLink, and data-platform has no flow logs');
  assert.ok(L('peering', 'vpc-0b2b2c3d4e5f60020').usage.ports.some((p) => p.port === 6379));
  assert.equal(L('vpn', 'transit').usage.hourly.length, 24);
  const f = (await db.query(`SELECT control, item_name, title FROM net_findings WHERE status = 'open' AND control IN ('net.link-unused', 'net.open-port-unused') ORDER BY control, title`)).rows;
  assert.ok(f.some((x) => x.control === 'net.link-unused' && /prod-core ↔ vpc-0c9c9c9c9c9c90099/.test(x.title)), JSON.stringify(f));
  assert.ok(f.some((x) => x.control === 'net.link-unused' && /office-hq/.test(x.title)));
  assert.ok(f.some((x) => x.control === 'net.open-port-unused' && /tcp 80 on payments-web/.test(x.title)));
  assert.ok(!f.some((x) => /tcp 22 on bastion/.test(x.title)), 'SSH on the bastion is used');
  const bastion = o.exposures.find((e) => e.id === 'eni-0a100000000bastion');
  assert.ok(bastion.ports[0].seen.accepted > 0 && bastion.reached[0].port === 22);
  // a bucket the scanner may not read
  await db.query('DELETE FROM net_flow_files'); await db.query('DELETE FROM net_flow_reads');
  process.env.DEMO_FLOW_DENIED = '1';
  try { const x = await flows.flowTick(); assert.equal(x.errors, 1); } finally { delete process.env.DEMO_FLOW_DENIED; }
  assert.match((await db.query('SELECT error FROM net_flow_reads')).rows[0].error, /not allowed to read s3:\/\/acme-flow-logs/);
});

test('a read that is refused is kept apart; a finding that goes away is resolved; turning it off stops reads', async () => {
  // the office VPN is fixed: its finding resolves on the next read
  const items = demoAwsNetwork(PROD, 'us-east-1').items.map((i) => (i.type === 'vpn' && i.name === 'office-hq' ? { ...i, data: { ...i.data, tunnels: i.data.tunnels.map((t) => ({ ...t, status: 'UP' })) } } : i));
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, items, skipped: ['ec2:DescribeFlowLogs'] });
  await sync.analyzeAndFile();
  assert.equal((await db.query(`SELECT status FROM net_findings WHERE control = 'net.vpn-down' AND item_name = 'office-hq'`)).rows[0].status, 'resolved');
  assert.deepEqual((await db.query(`SELECT skipped FROM net_reads WHERE owner = $1`, [PROD])).rows[0].skipped, ['ec2:DescribeFlowLogs']);
  // an error keeps what was stored
  const before = (await db.query(`SELECT count(*)::int AS n FROM net_items WHERE owner = $1`, [PROD])).rows[0].n;
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, error: 'AccessDenied' });
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM net_items WHERE owner = $1`, [PROD])).rows[0].n, before);
  assert.equal((await db.query(`SELECT error FROM net_reads WHERE owner = $1`, [PROD])).rows[0].error, 'AccessDenied');

  // a net.* control turned off on the Policy page: its open findings close at once, and stay closed when filed again
  const { setOverride } = await import('../src/controls.js');
  const r = await setOverride({ id: null }, 'net.sg-unused', { enabled: false });
  assert.ok(r.findingsChanged >= 1);
  assert.notEqual(await sync.networkTick(), null, 'the policy changed: findings filed again with no read due');
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM net_findings WHERE control = 'net.sg-unused' AND status = 'open'`)).rows[0].n, 0);
  await setOverride({ id: null }, 'net.sg-unused', { enabled: true });

  await ext.setExtension('networking', false, null);
  await ext.enabledExtensions({ fresh: true });
  await sync.requestNetworkRead();
  assert.equal(await sync.networkTick(), null);
  const l = await ext.listExtensions();
  assert.equal(l.find((x) => x.key === 'networking').enabled, false);
});
