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
const { flowRouter, aggregate, parseFlowText, s3Dest, fileTime, dayPrefix, folderOf, fileStem, planFlowLogs, countFlowFile, foldPorts, openPorts, flowState, LOOKBACK_DAYS } = await import('../src/network/flows.js');
const { demoFlowKeys, demoFlowFile, DEMO_SHARED_VPC, DEMO_SHARED_WITH, DEMO_GCP_SERVICE_IDLE, DEMO_FLOW_LOG, DEMO_FLOW_LOG_REJECTS } = await import('../src/network/demo.js');
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
  assert.deepEqual(sev(r, 'net.flow-logs-off'), ['data-platform:medium', 'shared-apps:medium'], 'prod-core has flow logs; empty default VPCs are not counted');
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

test("a shared VPC (AWS RAM): one VPC under its owner, each member's part of it, and the owner's routes for all", () => {
  const r = analyzeNetwork(demoItems(), estate);
  const ids = r.graph.nodes.filter((n) => n.nativeId === DEMO_SHARED_VPC).map((n) => n.id).sort();
  assert.deepEqual(ids, [`aws:slice:${DATA}:${DEMO_SHARED_VPC}`, `aws:vpc:${PROD}:${DEMO_SHARED_VPC}`], 'drawn once, plus the member slice; not once per account that reads it');
  const v = r.graph.nodes.find((n) => n.id === `aws:vpc:${PROD}:${DEMO_SHARED_VPC}`);
  assert.equal(v.shared, true);
  assert.equal(v.interfaces, 3, "the member's interfaces count once though both accounts read them");
  assert.deepEqual(v.tenants.map((t) => `${t.account}:${t.owner ? 'owner' : t.via.join('+')}:${t.interfaces}`),
    [`${PROD}:owner:1`, `${DATA}:interfaces+ram+read:2`, `${DEMO_SHARED_WITH}:ram:0`]);
  // the member's API has a public address in the owner's public subnet: exposed, in the shared VPC, line to the internet
  const api = r.exposures.find((e) => e.name.startsWith('orders-api'));
  assert.deepEqual([api.owner, api.vpcOwner, api.severity], [DATA, PROD, 'low']);
  assert.equal(v.exposed, 1);
  assert.ok(r.graph.links.some((l) => l.kind === 'internet' && l.from === v.id && l.ingress === 1));
  assert.ok(r.graph.links.some((l) => l.kind === 'share' && l.from === `aws:slice:${DATA}:${DEMO_SHARED_VPC}` && l.to === v.id));
  // shared with an account outside the estate: a finding; inside the organisation: none
  assert.deepEqual(sev(r, 'net.vpc-shared-external'), ['shared-apps-subnets:medium']);
  assert.equal(sev(analyzeNetwork(demoItems(), { ...estate, orgAccounts: new Map([[DEMO_SHARED_WITH, 'ops']]) }), 'net.vpc-shared-external').length, 0);
  // a member read alone (network account not connected): still one VPC, under its real owner, routes unknown
  const alone = analyzeNetwork(demoItems().filter((i) => i.owner !== PROD), { ...estate, awsAccounts: new Map([[DATA, { name: 'data-platform-stg' }]]) });
  const lone = alone.graph.nodes.find((n) => n.kind === 'vpc' && n.nativeId === DEMO_SHARED_VPC);
  assert.deepEqual([lone.owner, lone.ownerNotRead, lone.interfaces], [PROD, true, 2]);
  // flow logs: the member's interface travels the owner's route table out through the owner's internet gateway
  const route = flowRouter(demoItems(), r.graph);
  const x = route({ 'interface-id': 'eni-0c300000000orders', srcaddr: '198.51.100.9', dstaddr: '10.30.0.20', srcport: '51000', dstport: '443', protocol: '6' });
  assert.equal(x.side, v.id);
  assert.deepEqual(x.links, [r.graph.links.find((l) => l.kind === 'internet' && l.from === v.id).id]);
  assert.equal(x.exposure, 'eni-0c300000000orders');
});

test('a Google Cloud Shared VPC: service projects drawn in the host network they run in, joined to it', () => {
  const CI = 'projects/acme-shared-ci/global/networks/ci', TRANSIT = 'projects/acme-shared-ci/global/networks/transit';
  const r = analyzeNetwork(demoItems(), estate);
  const ci = r.graph.nodes.find((n) => n.id === `gcp:net:${CI}`);
  assert.equal(ci.shared, true);
  assert.deepEqual(ci.tenants.map((t) => `${t.account}:${t.owner ? 'host' : t.via.join('+')}:${t.instances}:${t.read}`),
    ['acme-shared-ci:host:1:true', 'acme-payments-prod:instances+xpn:1:true', `${DEMO_GCP_SERVICE_IDLE}:xpn:0:false`]);
  assert.ok(ci.tenants.every((t) => t.owner || t.yours), 'a service project is in the host organization');
  // payments runs in ci, so it has a part there and none in transit, which it may use but does not
  const slices = r.graph.nodes.filter((n) => n.kind === 'slice' && n.cloud === 'gcp');
  assert.deepEqual(slices.map((n) => n.id), [`gcp:slice:acme-payments-prod:${CI}`]);
  assert.equal(slices[0].instances, 1);
  const share = r.graph.links.find((l) => l.kind === 'share' && l.from === slices[0].id);
  assert.deepEqual([share.to, share.crossProject], [`gcp:net:${CI}`, true]);
  assert.equal(r.graph.nodes.find((n) => n.id === `gcp:net:${TRANSIT}`).tenants.find((t) => t.account === 'acme-payments-prod').instances, 0);
  // lines between projects say so: Private Service Connect across projects, NCC spokes in the hub's own project
  assert.equal(r.graph.links.find((l) => l.kind === 'psc').crossProject, true);
  assert.ok(r.graph.links.filter((l) => l.kind === 'ncc').every((l) => l.crossProject === false));

  // a service project's VM with an external address reachable on SSH: exposed, and counted on the host's network
  const withIp = demoItems().map((i) => (i.id.endsWith('/instances/payments-batch-1')
    ? { ...i, data: { ...i.data, tags: ['ssh'], interfaces: i.data.interfaces.map((y) => ({ ...y, natIps: ['198.51.100.31'] })) } } : i));
  const r2 = analyzeNetwork(withIp, estate);
  const e = r2.exposures.find((x) => x.name === 'payments-batch-1');
  assert.deepEqual([e.owner, e.vpcOwner, e.severity], ['acme-payments-prod', 'acme-shared-ci', 'high']);
  assert.equal(r2.graph.nodes.find((n) => n.id === `gcp:net:${CI}`).exposed, 2, "the host's runner and the service project's VM");
  assert.equal(r2.graph.nodes.find((n) => n.id === `gcp:slice:acme-payments-prod:${CI}`).exposed, 1);

  // attached and running nothing yet: drawn on the host's busiest network, once
  const attached = demoItems().map((i) => (i.type === 'shared-vpc' ? { ...i, data: { ...i.data, services: [...i.data.services, 'acme-data-stg'] } } : i));
  const idle = analyzeNetwork(attached, estate).graph.nodes.filter((n) => n.kind === 'slice' && n.owner === 'acme-data-stg');
  assert.deepEqual(idle.map((n) => [n.nativeId, n.attachedOnly]), [[CI, true]]);

  // the host not connected: its network is known from the service project's VM, under the host, marked so
  const alone = analyzeNetwork(demoItems().filter((i) => i.owner !== 'acme-shared-ci'), { ...estate, gcpProjects: new Map([['acme-payments-prod', {}], ['acme-data-stg', {}]]) });
  const lone = alone.graph.nodes.find((n) => n.id === `gcp:net:${CI}`);
  assert.deepEqual([lone.owner, lone.stub, lone.ownerNotRead], ['acme-shared-ci', true, true]);
  assert.ok(alone.graph.links.some((l) => l.kind === 'share' && l.from === `gcp:slice:acme-payments-prod:${CI}` && l.to === lone.id));
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

test('flow log folders: a day or an hour, plain or Hive-style; a flow log lists only its own files', () => {
  const t = Date.UTC(2026, 2, 4, 7, 30), base = { prefix: 'vpc', account: PROD, region: 'ap-southeast-3' };
  assert.deepEqual(folderOf(base, t), { prefix: `vpc/AWSLogs/${PROD}/vpcflowlogs/ap-southeast-3/2026/03/04/`, start: Date.UTC(2026, 2, 4), end: Date.UTC(2026, 2, 5) });
  assert.equal(folderOf({ ...base, perHour: true }, t).prefix, `vpc/AWSLogs/${PROD}/vpcflowlogs/ap-southeast-3/2026/03/04/07/`);
  assert.equal(folderOf({ ...base, perHour: true }, t).end - folderOf({ ...base, perHour: true }, t).start, 36e5);
  assert.equal(folderOf({ ...base, hive: true, perHour: true }, t).prefix, `vpc/AWSLogs/aws-account-id=${PROD}/aws-service=vpcflowlogs/aws-region=ap-southeast-3/year=2026/month=03/day=04/hour=07/`);
  assert.equal(fileStem(base, 'fl-0123'), `${PROD}_vpcflowlogs_ap-southeast-3_fl-0123_`);
  // the demo bucket answers a folder and the start of a file name, after a key, as S3 does
  const day = dayPrefix({ prefix: '', account: PROD, region: 'us-east-1' }, Date.now() - 2 * 864e5), all = demoFlowKeys({ bucket: 'acme-flow-logs', prefix: day });
  const mine = demoFlowKeys({ bucket: 'acme-flow-logs', prefix: day + fileStem({ account: PROD, region: 'us-east-1' }, DEMO_FLOW_LOG) });
  assert.equal(mine.length, 24); assert.deepEqual(mine, all);
  assert.deepEqual(demoFlowKeys({ bucket: 'acme-flow-logs', prefix: day + fileStem({ account: PROD, region: 'us-east-1' }, 'fl-other') }), []);
  assert.deepEqual(demoFlowKeys({ bucket: 'acme-flow-logs', prefix: day, startAfter: all[20].key }).map((k) => k.key), all.slice(21).map((k) => k.key));
});

test('which flow logs are read: one per VPC and kind of traffic, a VPC\'s own first; what cannot show a line unused says so', () => {
  const fl = (id, resource, data = {}, extra = {}) => ({ cloud: 'aws', type: 'flow-log', id, owner: PROD, region: 'us-east-1', vpc: /^vpc-/.test(resource) ? resource : null, ...extra,
    data: { resource, status: 'ACTIVE', traffic: 'ALL', destination: 's3', arn: 'arn:aws:s3:::acme-flow-logs', fileFormat: 'plain-text', ...data } });
  const items = [{ cloud: 'aws', type: 'subnet', id: 'subnet-1', owner: PROD, vpc: 'vpc-a', data: {} }, { cloud: 'aws', type: 'subnet', id: 'subnet-2', owner: PROD, vpc: 'vpc-c', data: {} }];
  const fls = [
    fl('fl-1', 'vpc-a', {}, {}), fl('fl-2', 'vpc-a', { traffic: 'ACCEPT' }), fl('fl-3', 'vpc-a', { traffic: 'REJECT', arn: 'arn:aws:s3:::acme-security/vpc' }),
    fl('fl-4', 'vpc-b', { traffic: 'ACCEPT' }), fl('fl-5', 'vpc-b', { traffic: 'REJECT' }),
    fl('fl-6', 'subnet-1'), fl('fl-7', 'subnet-2'), fl('fl-8', 'tgw-0a1'),
    fl('fl-9', 'vpc-d', { destination: 'cloud-watch-logs', arn: 'arn:aws:logs:us-east-1:111111111111:log-group:vpc' }), fl('fl-10', 'vpc-d', { fileFormat: 'parquet' }),
    fl('fl-11', 'vpc-e', { format: '${version} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${bytes} ${start} ${action}' }),
    fl('fl-13', 'vpc-f', { created: '2025-05-01T00:00:00Z' }), fl('fl-12', 'vpc-f', { created: '2025-01-01T00:00:00Z', deliverStatus: 'FAILED', deliverError: 'Access error' }),
  ];
  const plan = planFlowLogs(fls, items);
  const read = Object.fromEntries(plan.read.map((x) => [x.fl.id, x])), skip = Object.fromEntries(plan.skip.map((x) => [x.fl.id, x.note]));
  assert.deepEqual(Object.keys(read).sort(), ['fl-1', 'fl-12', 'fl-4', 'fl-5', 'fl-7']);
  assert.match(skip['fl-2'], /fl-1 already logs this VPC's traffic/); assert.match(skip['fl-3'], /count it twice/);
  assert.match(skip['fl-6'], /fl-1 already logs this subnet's traffic/, "the VPC's flow log has the subnet's records");
  assert.deepEqual([read['fl-1'].covers, read['fl-4'].covers, read['fl-5'].covers, read['fl-7'].covers], [true, true, false, false]);
  assert.match(read['fl-5'].info, /rejected traffic only/); assert.match(read['fl-7'].info, /subnet flow log/);
  assert.equal(read['fl-7'].vpcNode, `aws:vpc:${PROD}:vpc-c`);
  assert.match(skip['fl-8'], /transit gateway flow log/); assert.match(skip['fl-9'], /CloudWatch Logs/); assert.match(skip['fl-10'], /Parquet/);
  assert.match(skip['fl-11'], /leaves out interface-id/);
  assert.match(read['fl-12'].info, /AWS says delivery fails: Access error/, 'the oldest of two alike is read');
  // one being read stays read; one that fails gives way to one that does not
  const working = new Map([['fl-13', { front: new Date(), status: 'read' }]]);
  assert.ok(planFlowLogs(fls, items, working).read.some((x) => x.fl.id === 'fl-13'));
  const failing = new Map([['fl-1', { error: 'AccessDenied', status: 'read' }]]);
  const p2 = planFlowLogs(fls, items, failing);
  assert.deepEqual(p2.read.filter((x) => x.vpcNode === `aws:vpc:${PROD}:vpc-a`).map((x) => x.fl.id).sort(), ['fl-2', 'fl-3'], 'accepted and rejected apart, while fl-1 cannot be read');
});

test('flow log files are counted as they stream; refused ports and long port tails fold together', async () => {
  const items = demoItems(), a = analyzeNetwork(items, estate), route = flowRouter(items, a.graph);
  const key = demoFlowKeys({ bucket: 'acme-flow-logs', prefix: dayPrefix({ prefix: '', account: PROD, region: 'us-east-1' }, Date.now() - 864e5) })[5].key, buf = demoFlowFile(key);
  const streamed = { links: new Map(), exposure: new Map() };
  const r = await countFlowFile(buf, route, streamed);
  const whole = aggregate([...parseFlowText(zlib.gunzipSync(buf).toString())], route);
  assert.equal(r.records, [...parseFlowText(zlib.gunzipSync(buf).toString())].length);
  assert.deepEqual([...streamed.links.keys()].sort(), [...whole.links.keys()].sort());
  assert.deepEqual([...streamed.links.values()].map((x) => x.bytes).sort(), [...whole.links.values()].map((x) => x.bytes).sort());
  // refused traffic is one row per line, not per port
  assert.ok([...streamed.links.values()].filter((x) => x.action === 'REJECT').every((x) => x.port === 0));
  // a file in a format that leaves out what puts a record on a line counts nothing
  const odd = zlib.gzipSync('version srcaddr dstaddr srcport dstport protocol packets start end action log-status\n2 10.0.0.1 10.0.0.2 1 22 6 1 0 60 ACCEPT OK\n');
  assert.deepEqual(await countFlowFile(odd, route, { links: new Map(), exposure: new Map() }), { records: 0, missing: ['interface-id', 'bytes'] });
  await assert.rejects(countFlowFile(buf.subarray(0, Math.floor(buf.length / 2)), route, { links: new Map(), exposure: new Map() }), 'a cut-off file says so (the reader passes it over, its part dropped)');
  // a big file streams through in chunks: 60,000 records, the same totals as reading it whole
  const head = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status';
  const lines = Array.from({ length: 60000 }, (_, i) => `2 ${PROD} eni-0a100000000bastion 192.0.2.${i % 200} 10.10.0.20 ${40000 + (i % 999)} 22 6 3 ${100 + (i % 7)} ${1700000000 + i} ${1700000060 + i} ACCEPT OK`);
  const bigBuf = zlib.gzipSync(`${head}\n${lines.join('\n')}\n`), big = { links: new Map(), exposure: new Map() };
  assert.equal((await countFlowFile(bigBuf, route, big)).records, 60000);
  assert.equal([...big.exposure.values()].reduce((n, x) => n + x.records, 0), 60000);
  assert.equal([...big.exposure.values()].reduce((n, x) => n + x.bytes, 0), lines.reduce((n, l) => n + Number(l.split(' ')[9]), 0));

  // the internet on a public target: ports open to it and admin or database ports apart, the rest are "other ports"
  const open = openPorts(a.exposures), bastion = 'eni-0a100000000bastion';
  assert.deepEqual(open.get(bastion), [{ proto: 'tcp', ranges: [[22, 22]] }]);
  const rec = (port, action) => ({ 'interface-id': bastion, srcaddr: '203.0.113.9', dstaddr: '10.10.0.20', srcport: '51000', dstport: String(port), protocol: '6', bytes: '60', packets: '1', start: '1700000000', action });
  const ex = aggregate([rec(22, 'ACCEPT'), rec(8443, 'REJECT'), rec(8444, 'REJECT'), rec(3389, 'REJECT'), rec(9443, 'ACCEPT')], route, undefined, { open });
  assert.deepEqual([...ex.exposure.values()].map((x) => `${x.port}:${x.action}:${x.records}`).sort(), ['0:ACCEPT:1', '0:REJECT:2', '22:ACCEPT:1', '3389:REJECT:1']);
  // past 40 ports on one line in an hour, the quietest fold into port 0
  const rows = new Map(Array.from({ length: 50 }, (_, i) => [`k${i}`, { hour: 0, link: 'l', side: 's', dir: 'out', port: 1000 + i, proto: 'udp', action: 'ACCEPT', bytes: 100 + i, packets: 1, records: 1 }]));
  const folded = [...foldPorts(rows).values()];
  assert.equal(folded.length, 41);
  assert.deepEqual(folded.find((x) => x.port === 0), { hour: 0, link: 'l', side: 's', dir: 'out', port: 0, proto: 'udp', action: 'ACCEPT', bytes: 100 * 10 + 45, packets: 10, records: 10 });
  assert.ok(folded.some((x) => x.port === 1049) && !folded.some((x) => x.port === 1000));
});

test('flow log coverage: a hub line needs every VPC behind it; nothing is unused longer than it has been there; stale evidence holds findings', () => {
  const items = demoItems(), now = Date.now(), d = 864e5;
  const prodNode = `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`;
  const run = (cover, its = items) => analyzeNetwork(its, { ...estate, now }, undefined, { links: new Map(), exposure: new Map(), coverage: new Map(cover) });
  const week = (node, until = now) => [node, { since: new Date(now - 7 * d), until: new Date(until) }];
  const a = run([week(prodNode)]);
  const line = (r, kind, label) => r.graph.links.find((l) => l.kind === kind && [l.from, l.to].some((id) => r.graph.nodes.find((n) => n.id === id)?.label === label));
  // prod-core's flow logs cannot vouch for data-platform's attachment, nor for the office VPN on the hub that both use
  const dataAtt = line(a, 'tgw', 'data-platform'), office = line(a, 'vpn', 'office-hq-firewall'), vendor = line(a, 'peering', 'vpc-0c9c9c9c9c9c90099');
  assert.equal(dataAtt.usage.state, 'unknown'); assert.deepEqual(dataAtt.usage.unlogged, [`aws:vpc:${DATA}:vpc-0b2b2c3d4e5f60020`]);
  assert.equal(office.usage.state, 'unknown'); assert.ok(office.usage.unlogged.includes(`aws:vpc:${DATA}:vpc-0b2b2c3d4e5f60020`) && !office.usage.unlogged.includes(prodNode));
  assert.equal(vendor.usage.state, 'unused', "prod-core's own peering it does see whole");
  const unused = a.findings.filter((f) => f.control === 'net.link-unused');
  assert.ok(unused.some((f) => f.nativeId === 'pcx-0a100000000vendor'));
  assert.ok(!unused.some((f) => f.nativeId === 'tgw-attach-0a1000000data' || /office-hq-firewall/.test(f.title)), unused.map((f) => f.title).join(' | '));
  // with every VPC behind the hub read, the office VPN can be called unused
  const behindHub = a.graph.links.filter((l) => l.kind === 'tgw').map((l) => (l.from.startsWith('aws:vpc:') ? l.from : l.to));
  assert.equal(line(run(behindHub.map((n) => week(n))), 'vpn', 'office-hq-firewall').usage.state, 'unused');
  // a peering first seen two days ago is not unused, whatever was read before it was there
  const young = items.map((i) => (i.type === 'peering' && i.id === 'pcx-0a100000000vendor' ? { ...i, firstSeen: new Date(now - 2 * d).toISOString() } : i));
  const y = line(run([week(prodNode)], young), 'peering', 'vpc-0c9c9c9c9c9c90099');
  assert.deepEqual([y.usage.state, y.usage.coveredDays, !!y.usage.firstSeen], ['quiet', 2, true]);
  // flow logs not read for 10 hours: not known now, and the finding it had is held, not resolved
  const stale = run([week(prodNode, now - 10 * 36e5)]);
  assert.equal(line(stale, 'peering', 'vpc-0c9c9c9c9c9c90099').usage.state, 'unknown');
  assert.equal(stale.findings.filter((f) => f.control === 'net.link-unused').length, 0);
  assert.ok(stale.held.includes(`net.link-unused|aws|${PROD}|${vendor.id}`), stale.held.join(' | '));
  assert.ok(stale.held.every((k) => !k.includes(dataAtt.id)), 'what was never known is not held');
});

test('flow records: an interface not read yet is placed by its address; transit gateway interfaces and both ends are not counted twice', () => {
  const tgwEni = { cloud: 'aws', owner: PROD, type: 'eni', id: 'eni-0a10000000tgw0001', vpc: 'vpc-0a1b2c3d4e5f60010', name: 'tgw',
    data: { subnet: 'subnet-0a1000000000app', privateIp: '10.10.10.200', publicIps: [], groups: [], kind: 'transit_gateway', description: 'Network Interface for Transit Gateway Attachment' } };
  const items = [...demoItems(), tgwEni], a = analyzeNetwork(items, estate);
  const prodNode = `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`, dataNode = `aws:vpc:${DATA}:vpc-0b2b2c3d4e5f60020`;
  const toData = a.graph.links.find((l) => l.kind === 'peering' && [l.from, l.to].includes(dataNode) && [l.from, l.to].includes(prodNode)).id;
  const rec = (eni, src, dst, sp, dp, action = 'ACCEPT', start = '1763700000') => ({ 'interface-id': eni, srcaddr: src, dstaddr: dst, srcport: String(sp), dstport: String(dp), protocol: '6', bytes: '1000', packets: '5', start, action });
  const route = flowRouter(items, a.graph);
  // an ECS task started after the last networking read: its record counts on the peering it went over
  assert.equal(route(rec('eni-0a1000000task0009', '10.10.10.99', '10.20.0.15', 44321, 5432)), null, 'without the flow log it came from, it cannot be placed');
  assert.deepEqual(route(rec('eni-0a1000000task0009', '10.10.10.99', '10.20.0.15', 44321, 5432), prodNode).links, [toData]);
  assert.equal(route(rec('eni-0a1000000task0009', '198.51.100.7', '10.10.10.99', 51000, 443), prodNode).exposure, null, 'not on the map, so not an exposure');
  // the transit gateway's interface: what this VPC sends is counted at the sender, what passes through is kept
  assert.equal(route(rec(tgwEni.id, '10.10.10.15', '10.20.0.15', 44321, 5432)), null);
  assert.ok(route(rec(tgwEni.id, '10.20.0.15', '10.128.0.9', 44321, 443)));
  // both ends read: accepted traffic counted where it leaves, refusals where they happen, and only from when the other end was read
  const both = flowRouter(items, a.graph, { logged: new Map([[dataNode, 1763600000e3]]) });
  const count = (records) => [...aggregate(records, both).links.values()].filter((x) => x.link === toData).map((x) => `${x.action}:${x.bytes}`).sort();
  assert.deepEqual(count([rec('eni-0a1000000000app01', '10.10.10.15', '10.20.0.15', 44321, 5432), rec('eni-0a1000000000app01', '10.20.0.15', '10.10.10.15', 5432, 44321)]), ['ACCEPT:1000']);
  assert.deepEqual(count([rec('eni-0a1000000000app01', '10.20.0.15', '10.10.10.15', 5432, 44321, 'REJECT')]), ['REJECT:1000']);
  assert.deepEqual(count([rec('eni-0a1000000000app01', '10.20.0.15', '10.10.10.15', 5432, 44321, 'ACCEPT', '1763500000')]), ['ACCEPT:1000'], 'before the other end had a flow log');
});

test('a transit gateway route out of the estate is looked up in the route table of the VPC\'s own attachment', () => {
  const items = demoItems().map((i) => (i.type === 'tgw-route-table' ? { ...i, data: { ...i.data, associations: i.data.associations.filter((x) => x.attachment !== 'tgw-attach-0a1000000prod') } } : i));
  const main = items.find((i) => i.type === 'tgw-route-table');
  // prod-core's attachment sits in a segment of its own, whose route to the office goes over the Google Cloud VPN instead
  items.push({ ...main, id: 'tgw-rtb-0a1000000prodseg', name: 'prod segment', data: { ...main.data, default: false, associations: [{ attachment: 'tgw-attach-0a1000000prod', resourceType: 'vpc' }],
    routes: [{ dest: '192.168.0.0/16', type: 'static', state: 'active', attachments: [{ attachment: 'tgw-attach-0a1000000vpn0', resourceType: 'vpn', resourceId: 'vpn-0a1000000000gcp0' }] }] } });
  const a = analyzeNetwork(items, estate), route = flowRouter(items, a.graph);
  const r = route({ 'interface-id': 'eni-0a1000000000app01', srcaddr: '10.10.10.15', dstaddr: '192.168.1.10', srcport: '44321', dstport: '443', protocol: '6', bytes: '1', packets: '1', start: '1763700000', action: 'ACCEPT' });
  const vpn = (id) => a.graph.links.find((l) => l.id === id);
  assert.ok(r.links.some((id) => vpn(id)?.kind === 'vpn' && vpn(id).vpns.some((v) => v.id === 'vpn-0a1000000000gcp0')), JSON.stringify(r.links));
  assert.ok(!r.links.some((id) => vpn(id)?.vpns?.some((v) => v.id === 'vpn-0a10000000office')), "not the office VPN of another segment's table");
});

test("a flow log's reading state, as the page says it", () => {
  const now = Date.UTC(2026, 4, 10, 12), fl = { data: {} }, h = 36e5;
  assert.equal(flowState(fl, null, now).state, 'waiting');
  assert.equal(flowState(fl, { status: 'skipped', note: 'not read: fl-1 already logs it', error: 'old' }, now).error, null);
  assert.equal(flowState(fl, { status: 'read', error: 'AccessDenied' }, now).state, 'error');
  const reading = flowState(fl, { status: 'read', front: new Date(now), back: new Date(now - 2 * 864e5), pending: 0, last_time: new Date(now - 5 * 6e4) }, now);
  assert.deepEqual([reading.state, reading.historyDays], ['catching-up', 2]);
  const done = flowState(fl, { status: 'read', front: new Date(now), back: new Date(now - LOOKBACK_DAYS * 864e5 - h), pending: 0 }, now);
  assert.deepEqual([done.state, done.historyDays], ['current', LOOKBACK_DAYS]);
  assert.equal(flowState(fl, { status: 'read', front: new Date(now), back: new Date(now - 9 * 864e5), pending: 3 }, now).state, 'catching-up', 'new files still to read');
  // a flow log turned on two days ago has two days of history to read, no more
  const young = flowState({ data: { created: new Date(now - 2 * 864e5).toISOString() } }, { status: 'read', front: new Date(now), back: new Date(now - 2 * 864e5 - h), pending: 0 }, now);
  assert.deepEqual([young.state, young.historyDays], ['current', 2]);
});

test('Google Cloud firewall: a deny before an allow takes it back; no source is anywhere; protocols as written; which tier comes first', () => {
  const P = 'made-up-proj', net = `projects/${P}/global/networks/core`;
  const g = (type, id, data, extra = {}) => ({ cloud: 'gcp', owner: P, type, id, name: id.split('/').pop(), vpc: net, region: null, data, ...extra });
  const network = (d = {}) => g('network', net, { autoSubnets: false, peerings: [], legacy: false, ...d });
  const web = g('instance', `projects/${P}/zones/z1/instances/web-1`, { status: 'RUNNING', tags: ['web'], serviceAccounts: [], interfaces: [{ network: net, subnet: 's1', ip: '10.0.0.5', natIps: ['198.51.100.10'] }] }, { region: 'z1' });
  const fw = (name, d) => g('firewall', `projects/${P}/global/firewalls/${name}`, { direction: 'INGRESS', priority: 1000, action: 'allow', rules: [], sourceRanges: [], destinationRanges: [], sourceTags: [],
    sourceServiceAccounts: [], targetTags: [], targetServiceAccounts: [], disabled: false, logging: false, ...d });
  const policy = (rules) => g('firewall-policy', `projects/${P}/global/firewallPolicies/made-up-policy`, { networks: [net], rules: rules.map((r) => ({ direction: 'INGRESS', disabled: false, sourceRanges: ['0.0.0.0/0'],
    destinationRanges: [], targetServiceAccounts: [], targetTags: [], logging: false, ...r })) }, { vpc: null });
  // the rules given, on one instance with an external address (and a network of its own when one is given)
  const run = (...extra) => {
    const r = analyzeNetwork([extra.find((x) => x.type === 'network') || network(), web, ...extra.filter((x) => x.type !== 'network')], { gcpProjects: new Map([[P, {}]]) });
    const fws = r.findings.filter((f) => /^net\.gcp-fw/.test(f.control));
    return { titles: fws.map((f) => f.title), details: fws.map((f) => f.detail), ports: r.exposures.find((e) => e.kind === 'instance')?.ports.map((x) => `${x.proto} ${x.ports}`) || [] };
  };
  const ssh = fw('allow-ssh', { rules: [{ proto: 'tcp', ports: ['22'] }], sourceRanges: ['0.0.0.0/0'] });
  const deny = (name, d) => fw(name, { action: 'deny', priority: 100, rules: [{ proto: 'tcp', ports: ['22'] }], sourceRanges: ['0.0.0.0/0'], ...d });
  assert.deepEqual(run(ssh).titles, ['Firewall rule allow-ssh opens SSH (22) to the internet']);
  // a deny from the internet with a higher priority, or the same (a deny wins a tie), takes it back
  assert.deepEqual(run(ssh, deny('deny-ssh')), { titles: [], details: [], ports: [] });
  assert.deepEqual(run(ssh, deny('deny-ssh-tie', { priority: 1000, rules: [{ proto: 'tcp' }] })).ports, []);
  // not one that comes after it, misses some of the internet, other instances, or only some destinations
  for (const d of [deny('later', { priority: 2000 }), deny('part', { sourceRanges: ['192.0.2.0/24'] }), deny('db-only', { targetTags: ['db'] }), deny('to-some', { destinationRanges: ['10.0.0.0/8'] }),
    deny('udp', { rules: [{ proto: 'udp', ports: ['22'] }] }), deny('v6-only', { sourceRanges: ['::/0'] })]) assert.deepEqual(run(ssh, d).ports, ['tcp 22'], d.name);
  // a deny of one port leaves the rest of an allow of everything
  const everything = fw('allow-all', { rules: [{ proto: 'all' }], sourceRanges: ['0.0.0.0/0'] });
  const most = run(everything, deny('deny-ssh'));
  assert.deepEqual(most.ports, ['tcp 0-21, 23-65535', 'udp every port', 'sctp every port']);
  assert.match(most.details[0], /every UDP and SCTP port/);
  assert.deepEqual(run(everything).ports, ['all every port']);
  // an ingress rule with no source at all is from any IPv4 address; one from tagged instances only is not
  assert.deepEqual(run(fw('rdp-nosource', { rules: [{ proto: 'tcp', ports: ['3389'] }] })), { titles: ['Firewall rule rdp-nosource opens RDP (3389) to the internet'],
    details: ['Ingress from 0.0.0.0/0 on RDP (3389) (every instance in the network); it reaches web-1 (198.51.100.10), with external addresses.'], ports: ['tcp 3389'] });
  assert.deepEqual(run(fw('rdp-from-bastion', { rules: [{ proto: 'tcp', ports: ['3389'] }], sourceTags: ['bastion'] })).ports, []);
  // UDP stays UDP
  assert.deepEqual(run(fw('allow-ike', { rules: [{ proto: 'udp', ports: ['500', '4500'] }], sourceRanges: ['0.0.0.0/0'] })), { titles: [], details: [], ports: ['udp 500, 4500'] });
  // every instance it applies to kept out by a deny: said so, and low
  const shielded = run(ssh, deny('deny-web', { targetTags: ['web'] }));
  assert.deepEqual([shielded.ports, shielded.details[0]], [[], 'Ingress from 0.0.0.0/0 on SSH (22) (every instance in the network); deny rules keep it from web-1, the instances it applies to today.']);
  // the network firewall policy comes after the VPC firewall rules, unless the network puts it first
  const policyDeny = policy([{ priority: 10, action: 'deny', layer4: [{ proto: 'tcp', ports: ['22'] }] }]);
  assert.deepEqual(run(ssh, policyDeny).ports, ['tcp 22']);
  assert.deepEqual(run(ssh, policyDeny, network({ policyOrder: 'BEFORE_CLASSIC_FIREWALL' })).ports, []);
  const policyAllow = policy([{ priority: 10, action: 'allow', layer4: [{ proto: 'tcp', ports: ['22'] }] }]);
  assert.deepEqual(run(policyAllow, deny('deny-ssh', { priority: 65000 })), { titles: [], details: [], ports: [] }, 'a VPC deny comes before the policy');
  assert.deepEqual(run(policyAllow).titles, ['Firewall policy made-up-policy, rule 10 opens SSH (22) to the internet']);
});

test('AWS: a Classic Load Balancer is known by its interfaces; overlapping VPCs on one transit gateway; flow logs of a VPC whose owner is not connected', () => {
  const a = (type, id, vpc, data, extra = {}) => ({ cloud: 'aws', owner: PROD, type, id, name: id, vpc, region: 'us-east-1', data, ...extra });
  const eni = (id, subnet, ip, description, groups) => a('eni', id, 'vpc-made1', { subnet, privateIp: '10.1.0.9', publicIp: ip, publicIps: [], groups, kind: 'interface', instance: null, description });
  const att = (id, vpc) => a('tgw-attachment', id, vpc, { tgw: 'tgw-made', tgwOwner: PROD, resourceType: 'vpc', resourceId: vpc, resourceOwner: PROD, state: 'available' });
  const items = [
    a('vpc', 'vpc-made1', 'vpc-made1', { cidrs: ['10.1.0.0/16'] }), a('vpc', 'vpc-made2', 'vpc-made2', { cidrs: ['10.1.128.0/17'] }), a('vpc', 'vpc-made3', 'vpc-made3', { cidrs: ['10.9.0.0/16'] }),
    a('subnet', 'subnet-pub1', 'vpc-made1', { cidr: '10.1.0.0/24' }), a('subnet', 'subnet-pub2', 'vpc-made1', { cidr: '10.1.1.0/24' }),
    a('route-table', 'rtb-1', 'vpc-made1', { main: true, subnets: [], routes: [{ dest: '0.0.0.0/0', target: { type: 'igw', id: 'igw-1' }, state: 'active' }] }),
    a('igw', 'igw-1', 'vpc-made1', { vpcs: ['vpc-made1'] }),
    a('sg', 'sg-clb', 'vpc-made1', { groupName: 'clb', isDefault: false, ingress: [{ proto: 'tcp', from: 443, to: 443, cidrs: ['0.0.0.0/0'], ipv6: [], groups: [], prefixLists: [] }], egress: [] }),
    // a Classic Load Balancer: an interface in each zone, "ELB <name>"; an Application Load Balancer's is "ELB app/…"
    eni('eni-clb1', 'subnet-pub1', '203.0.113.20', 'ELB legacy-web', ['sg-clb']), eni('eni-clb2', 'subnet-pub2', '203.0.113.21', 'ELB legacy-web', ['sg-clb']),
    eni('eni-alb1', 'subnet-pub1', '203.0.113.30', 'ELB app/made-up-alb/0123456789abcdef', ['sg-clb']),
    a('tgw', 'tgw-made', null, { owner: PROD }), att('tgw-attach-1', 'vpc-made1'), att('tgw-attach-2', 'vpc-made2'), att('tgw-attach-3', 'vpc-made3'),
  ];
  const est = { awsAccounts: new Map([[PROD, { name: 'payments-prod' }]]) };
  const r = analyzeNetwork(items, est);
  const lbs = r.exposures.filter((e) => e.kind === 'load-balancer');
  assert.deepEqual(lbs.map((e) => [e.name, e.addresses.sort(), e.ports.map((x) => `${x.proto} ${x.ports}`)]), [['legacy-web (Classic Load Balancer)', ['203.0.113.20', '203.0.113.21'], ['tcp 443']]]);
  assert.ok(!r.exposures.some((e) => e.kind === 'interface'), 'its interfaces, and the other load balancer\'s, are not counted on their own');
  // the two overlapping VPCs on the transit gateway, and not the third
  const overlap = (res) => res.findings.filter((f) => f.control === 'net.cidr-overlap').map((f) => f.title);
  assert.deepEqual(overlap(r), ['vpc-made1 and vpc-made2 use overlapping addresses on transit gateway tgw-made']);
  // with its route tables read: kept apart, nothing; routed to each other, the finding
  const rt = (id, assoc, to) => a('tgw-route-table', id, null, { tgw: 'tgw-made', default: false, associations: [{ attachment: assoc, resourceType: 'vpc', resourceId: null }],
    routes: to ? [{ dest: '10.1.128.0/17', type: 'propagated', state: 'active', attachments: [{ attachment: to, resourceType: 'vpc', resourceId: null }] }] : [] });
  assert.deepEqual(overlap(analyzeNetwork([...items, rt('tgw-rtb-a', 'tgw-attach-1'), rt('tgw-rtb-b', 'tgw-attach-2')], est)), []);
  const joined = analyzeNetwork([...items, rt('tgw-rtb-a', 'tgw-attach-1', 'tgw-attach-2'), rt('tgw-rtb-b', 'tgw-attach-2')], est).findings.find((f) => f.control === 'net.cidr-overlap');
  assert.match(joined.detail, /route tables send one to the other/);

  // a VPC shared with a connected member account whose owner is not connected: its flow logs cannot be seen from there
  const member = demoAwsNetwork(DATA, 'us-east-1').items.map((i) => ({ ...i, cloud: 'aws', owner: DATA }));
  const m = analyzeNetwork(member, { awsAccounts: new Map([[DATA, { name: 'data-platform-stg' }]]) });
  assert.ok(m.items.some((i) => i.type === 'vpc' && i.id === DEMO_SHARED_VPC && i.data.ownerNotRead));
  assert.ok(!m.findings.some((f) => f.control === 'net.flow-logs-off' && (f.vpc === DEMO_SHARED_VPC || f.nativeId === DEMO_SHARED_VPC)));
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
  // "Read now": asked for, and done by the next tick; when each owner was read is left alone until then
  const readAt = async () => (await db.query(`SELECT max(read_at) AS t FROM net_reads`)).rows[0].t.getTime();
  const was = await readAt();
  await sync.requestNetworkRead();
  assert.ok(await sync.pendingNetworkRead());
  assert.equal(await readAt(), was, 'asking for a read does not make the last read look older');
  assert.ok(await sync.networkTick());
  assert.equal(await sync.pendingNetworkRead(), null);
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
  // a Shared VPC network: the host's instance and the service project's, and who runs what
  assert.deepEqual(net.instances.map((i) => `${i.name}@${i.owner}`).sort(), ['ci-runner-1@acme-shared-ci', 'payments-batch-1@acme-payments-prod']);
  assert.deepEqual(net.tenants.map((t) => t.account), ['acme-shared-ci', 'acme-payments-prod', DEMO_GCP_SERVICE_IDLE]);
  // a service project's part of it: its own instances only, under the host's firewall rules
  const part = await api.networkDetail(owner, `gcp:slice:acme-payments-prod:projects/acme-shared-ci/global/networks/ci`);
  assert.equal(part.node.kind, 'slice');
  assert.equal(part.vpcNode, 'gcp:net:projects/acme-shared-ci/global/networks/ci');
  assert.deepEqual(part.instances.map((i) => i.name), ['payments-batch-1']);
  assert.ok(part.firewallRules.some((x) => x.name === 'allow-ssh-anywhere'));
  await assert.rejects(api.networkDetail(owner, 'aws:vpc:000:nope'), /Not found/);

  const list = await api.networkFindings(owner, { severity: 'high' });
  const bastion = list.items.find((x) => x.itemName === 'bastion');
  await assert.rejects(api.decideNetFinding(owner, bastion.id, { decision: 'expected', note: '' }), /why/);
  await api.decideNetFinding({ ...owner, id: null }, bastion.id, { decision: 'expected', note: 'IP-restricted at the edge' });
  assert.equal((await api.networkFindings(owner, { severity: 'high' })).items.find((x) => x.id === bastion.id).decision, 'expected');
  await api.undecideNetFinding(owner, bastion.id);

  // each finding says where it is drawn: a VPN that is down is its line, a blackhole route its transit gateway
  const all = (await api.networkFindings(owner, {})).items;
  const drawn = new Set([...o.nodes.map((n) => n.id), ...o.links.map((l) => l.id)]);
  assert.ok(all.filter((x) => x.target).every((x) => drawn.has(x.target)), 'every target is on the map');
  assert.ok(all.filter((x) => x.vpc).every((x) => x.target), 'everything in a VPC or network has one');
  const vpnDown = all.find((x) => x.control === 'net.vpn-down');
  assert.ok(vpnDown && o.links.find((l) => l.id === vpnDown.target)?.kind === 'vpn');
  assert.ok(o.linkFindings[vpnDown.target].some((x) => x.id === vpnDown.id), "the line's panel lists it");
  const hole = all.find((x) => x.control === 'net.tgw-blackhole');
  if (hole) {
    assert.match(hole.target, /^aws:tgw:/);
    assert.ok((await api.networkDetail(owner, hole.target)).findings.some((x) => x.control === 'net.tgw-blackhole'), "and the transit gateway's panel");
  }
  // the list is searched by what it shows: the account's name, the control
  const byName = (await api.networkFindings(owner, { q: 'data-platform-stg' })).items;
  assert.ok(byName.length && byName.some((x) => x.owner === DATA));
  assert.ok((await api.networkFindings(owner, { q: 'net.sg-admin-open' })).items.every((x) => x.control === 'net.sg-admin-open'));

  const inv = await api.networkInventory(owner, { type: 'sg' });
  assert.ok(inv.items.every((i) => i.type === 'sg') && inv.types.vpc >= 4);
  assert.ok((await api.networkInventory(owner, { q: '198.51.100.77' })).items.some((i) => i.name === 'ci-runner-1'));

  // a member limited to one AWS account: that account's networks, nothing from Google Cloud
  const acct = (await db.query(`SELECT id FROM cloud_accounts WHERE account_id = $1`, [DATA])).rows[0].id;
  const scoped = { id: null, scope_accounts: [acct] };
  const so = await api.networkOverview(scoped);
  assert.ok(so.nodes.filter((n) => !n.stub && n.cloud && !n.participantView).every((n) => n.cloud === 'aws' && n.owner === DATA), 'only its own VPCs in full');
  // the VPC payments-prod shares with it: there, with only its own part
  const sharedSeen = so.nodes.find((n) => n.nativeId === DEMO_SHARED_VPC && n.kind === 'vpc');
  assert.equal(sharedSeen.participantView, true);
  assert.deepEqual(sharedSeen.tenants.filter((t) => !t.hidden).map((t) => t.account), [DATA]);
  assert.equal(sharedSeen.findings, 0, "the owner's findings stay the owner's");
  const seenDetail = await api.networkDetail(scoped, sharedSeen.id);
  assert.ok(seenDetail.interfaces.length && seenDetail.interfaces.every((e) => e.account === DATA));
  assert.ok(seenDetail.securityGroups.every((g) => g.account === DATA), "the owner's security groups are not shown");
  const far = so.nodes.find((n) => n.id === `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`);
  assert.deepEqual([far.hidden, far.cidrs, far.worst], [true, [], 'none'], 'the other end of its peering: a name, nothing inside');
  assert.ok(!so.nodes.some((n) => n.cloud === 'gcp'));
  // which VPCs' flow logs would tell what a line carries: only VPCs it may see are named, the rest counted
  const named = new Set(so.nodes.filter((n) => !n.hidden).map((n) => n.id));
  assert.ok(so.links.every((l) => (l.usage?.unlogged || []).every((id) => named.has(id))), 'no VPC of another account by its ID');
  const peering = so.links.find((l) => l.kind === 'peering' && [l.from, l.to].includes(`aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`));
  assert.equal(peering.usage.unloggedHidden, 1);
  // and a VPC's panel draws the far end of its lines as the map does: a name, nothing inside
  const own = await api.networkDetail(scoped, `aws:vpc:${DATA}:vpc-0b2b2c3d4e5f60020`);
  const across = own.links.find((l) => l.id === peering.id);
  assert.deepEqual([across.other.hidden, across.other.cidrs, across.other.tenants, across.usage.unloggedHidden], [true, [], undefined, 1]);
  assert.ok(so.exposures.every((e) => e.cloud === 'aws' && e.owner === DATA));
  assert.ok((await api.networkFindings(scoped, {})).items.every((x) => x.cloud === 'aws' && x.owner === DATA));
  await assert.rejects(api.networkDetail(scoped, 'gcp:net:projects/acme-shared-ci/global/networks/ci'), /Not found/);
});

test('flow logs from S3: read once, a budget at a time; lines used, not used, not known; ports nobody uses', async () => {
  const flows = await import('../src/network/flows.js');
  const r = await flows.flowTick({ worker: 'wk-test-1' });
  assert.ok(r.files >= 7 * 24 && r.errors === 0, JSON.stringify(r));
  assert.ok(r.lists <= LOOKBACK_DAYS + 2, `a folder a day, its own files only: ${r.lists} listings`);
  assert.equal(await flows.flowTick({ worker: 'wk-test-2' }), null, 'every file is read once, and nothing is listed again within 5 minutes');
  // each step is noted with the worker that ran it; the last one that read something is kept apart
  const step = await flows.flowStep();
  assert.deepEqual([step.last.worker.id, step.last.result.files, step.last.work.files, step.last.runs], ['wk-test-2', 0, r.files, 2]);
  const reads = (await db.query('SELECT * FROM net_flow_reads')).rows;
  const main = reads.find((x) => x.flow_log === DEMO_FLOW_LOG), rejects = reads.find((x) => x.flow_log === DEMO_FLOW_LOG_REJECTS);
  assert.equal(main.bucket, 'acme-flow-logs');
  assert.ok(new Date(main.back).getTime() <= Date.now() - LOOKBACK_DAYS * 864e5 + 6e4 && main.status === 'read' && !main.pending, 'the whole lookback is read');
  assert.equal(rejects.status, 'skipped', 'the refusals-only flow log on the same VPC: its records are in the other');
  assert.match(rejects.note, new RegExp(`${DEMO_FLOW_LOG} already logs this VPC's traffic`));
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM net_flow_hourly WHERE action = 'REJECT' AND port <> 0`)).rows[0].n, 0, 'refusals by line, not by port');
  await sync.analyzeAndFile();
  (await import('../src/cache.js')).clearCache();
  const o = await api.networkOverview(owner);
  const L = (kind, has) => o.links.find((l) => l.kind === kind && (l.from.includes(has) || l.to.includes(has)));
  assert.equal(L('peering', 'vpc-0b2b2c3d4e5f60020').usage.state, 'used');
  assert.equal(L('peering', 'vpc-0c9c9c9c9c9c90099').usage.state, 'unused');
  assert.equal(L('vpn', 'transit').usage.state, 'used');
  // the office VPN hangs off the transit gateway every VPC behind it can use, and data-platform has no flow logs
  assert.equal(L('vpn', '198.51.100.200').usage.state, 'unknown', 'one read VPC cannot vouch for the others behind the hub');
  assert.ok(L('vpn', '198.51.100.200').usage.unlogged.includes(`aws:vpc:${DATA}:vpc-0b2b2c3d4e5f60020`));
  assert.equal(L('tgw', 'vpc-0b2b2c3d4e5f60020').usage.state, 'unknown', "nor for data-platform's own attachment");
  assert.equal(L('dx', 'dxcon').usage.state, 'used');
  assert.equal(L('peering', 'acme-data-stg').usage.state, 'unknown', 'only Google Cloud sees it');
  assert.equal(L('privatelink', 'vpc-0b2b2c3d4e5f60020').usage.state, 'unknown', 'only the consumer side can see PrivateLink, and data-platform has no flow logs');
  assert.ok(L('peering', 'vpc-0b2b2c3d4e5f60020').usage.ports.some((p) => p.port === 6379));
  assert.equal(L('vpn', 'transit').usage.hourly.length, 24);
  const f = (await db.query(`SELECT control, item_name, title FROM net_findings WHERE status = 'open' AND control IN ('net.link-unused', 'net.open-port-unused') ORDER BY control, title`)).rows;
  assert.ok(f.some((x) => x.control === 'net.link-unused' && /prod-core ↔ vpc-0c9c9c9c9c9c90099/.test(x.title)), JSON.stringify(f));
  assert.ok(!f.some((x) => x.control === 'net.link-unused' && /office-hq|data-platform ↔ hub/.test(x.title)), 'not filed on what prod-core alone cannot see');
  assert.ok(f.some((x) => x.control === 'net.open-port-unused' && /tcp 80 on payments-web/.test(x.title)));
  assert.ok(!f.some((x) => /tcp 22 on bastion/.test(x.title)), 'SSH on the bastion is used');
  const bastion = o.exposures.find((e) => e.id === 'eni-0a100000000bastion');
  assert.ok(bastion.ports[0].seen.accepted > 0 && bastion.reached[0].port === 22);
  // the page: every flow log and how far it is read, what is kept, an earlier day to replay
  assert.deepEqual(o.flowLogs.map((x) => `${x.flowLog}:${x.state}`), [`${DEMO_FLOW_LOG}:current`, `${DEMO_FLOW_LOG_REJECTS}:skipped`]);
  assert.equal(o.flowLogs[0].historyDays, LOOKBACK_DAYS);
  assert.ok(o.flow.storedBytes > 0 && o.flow.lookbackDays === LOOKBACK_DAYS && o.flow.keepDays === LOOKBACK_DAYS + 1);
  assert.equal(o.flow.step.last.worker.id, 'wk-test-2', 'the page says which worker reads them');
  // Operations → Workers: the reader, its last step, each flow log by state
  const { workerStatus } = await import('../src/workerStatus.js');
  const ops = (await workerStatus()).flow;
  assert.deepEqual([ops.last.worker.id, ops.counts.current, ops.counts.skipped, ops.flowLogs.find((x) => x.flowLog === DEMO_FLOW_LOG).vpc], ['wk-test-2', 1, 1, 'prod-core']);
  assert.ok(ops.settings.stepFiles > 0 && ops.settings.lookbackDays === LOOKBACK_DAYS);
  const vpcPanel = await api.networkDetail(owner, `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`);
  assert.deepEqual(vpcPanel.flowLogList.map((x) => x.state), ['current', 'skipped']);
  const out = o.links.find((l) => l.kind === 'internet' && [l.from, l.to].includes(`aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`));
  const today = await api.networkHours(owner, { day: 0 }), yesterday = await api.networkHours(owner, { day: 1 });
  assert.equal(new Date(yesterday.hourStart).getTime(), new Date(o.hourStart).getTime() - 864e5);
  assert.ok(today.hours[out.id].some((b) => b.bytes > 0) && yesterday.hours[out.id].length === 24 && yesterday.hours[out.id].some((b) => b.bytes > 0));
  assert.equal((await api.networkHours(owner, { day: 99 })).day, LOOKBACK_DAYS - 1, 'no further back than the days kept');
  const dataOnly = { id: null, scope_accounts: [(await db.query(`SELECT id FROM cloud_accounts WHERE account_id = $1`, [DATA])).rows[0].id] };
  assert.ok(!(out.id in (await api.networkHours(dataOnly, { day: 1 })).hours), "a member limited to another account does not see prod-core's way out");
  // a listing that found nothing new vouches for an idle VPC: covered past its newest file, while the reader is well
  const flowsMod = await import('../src/network/flows.js'), prodNode = `aws:vpc:${PROD}:vpc-0a1b2c3d4e5f60010`;
  assert.equal((await db.query('SELECT covers FROM net_flow_reads WHERE flow_log = $1', [DEMO_FLOW_LOG])).rows[0].covers, true);
  await db.query(`UPDATE net_flow_reads SET front = now() WHERE flow_log = $1`, [DEMO_FLOW_LOG]);
  const cov = (await flowsMod.loadUsage()).coverage.get(prodNode);
  assert.ok(new Date(cov.until) > new Date(cov.newest) && Date.now() - new Date(cov.until) < 6e4, JSON.stringify(cov));
  // the reader stops for a night: the vendor peering's finding (and the decision on it) stays, not resolved and reopened
  const vendorFinding = async () => (await db.query(`SELECT id, key, status, decision FROM net_findings WHERE control = 'net.link-unused' AND native_id = 'pcx-0a100000000vendor'`)).rows[0];
  await api.decideNetFinding({ ...owner, id: null }, (await vendorFinding()).id, { decision: 'expected', note: 'disaster recovery standby, idle by design' });
  await db.query(`UPDATE net_flow_files SET file_time = file_time - interval '10 hours'`); await db.query(`UPDATE net_flow_reads SET front = front - interval '10 hours'`);
  const stale = await sync.analyzeAndFile();
  assert.ok(stale.held.includes((await vendorFinding()).key), stale.held.join(' | '));
  assert.deepEqual([(await vendorFinding()).status, (await vendorFinding()).decision], ['open', 'expected']);
  // a bucket the scanner may not read
  await db.query('DELETE FROM net_flow_files'); await db.query('DELETE FROM net_flow_reads');
  process.env.DEMO_FLOW_DENIED = '1';
  try { const x = await flows.flowTick(); assert.equal(x.errors, 1); } finally { delete process.env.DEMO_FLOW_DENIED; }
  assert.match((await db.query('SELECT error FROM net_flow_reads WHERE flow_log = $1', [DEMO_FLOW_LOG])).rows[0].error, /not allowed to read s3:\/\/acme-flow-logs/);
  const advice = (await workerStatus()).advice.find((a) => /VPC flow log cannot be read/.test(a.title));
  assert.ok(advice?.level === 'warning' && /prod-core/.test(advice.detail), 'Operations says which one, and how to let it be read');
});

test('networking objects keep when they were first seen, read after read', async () => {
  const items = demoAwsNetwork(PROD, 'us-east-1').items;
  const firstSeen = async (type, id) => (await sync.loadItems()).find((i) => i.cloud === 'aws' && i.owner === PROD && i.type === type && i.id === id)?.firstSeen;
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, items });
  const old = await firstSeen('peering', 'pcx-0a100000000vendor');
  // a peering made since the last read is new now; what was there keeps its date (none, when there before the first read)
  const added = { ...items.find((i) => i.type === 'peering' && i.id === 'pcx-0a100000000vendor'), id: 'pcx-0a1000000000newer', name: 'newer' };
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, items: [...items, added] });
  assert.ok(Date.now() - new Date(await firstSeen('peering', 'pcx-0a1000000000newer')).getTime() < 60e3);
  assert.equal(String(await firstSeen('peering', 'pcx-0a100000000vendor')), String(old));
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, items: [...items, added] });
  const again = await firstSeen('peering', 'pcx-0a1000000000newer');
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, items: [...items, added] });
  assert.equal(String(await firstSeen('peering', 'pcx-0a1000000000newer')), String(again), 'kept, not renewed');
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, items });
});

const pad2 = (n) => String(n).padStart(2, '0');
const stampOf = (t) => { const d = new Date(t); return `${d.getUTCFullYear()}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}T${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}Z`; };
const emptyFlows = async () => { for (const t of ['net_flow_files', 'net_flow_reads', 'net_flow_hourly', 'net_flow_exposure']) await db.query(`DELETE FROM ${t}`); };

test('flow logs are listed as AWS delivers them: history a folder at a time, then only what is new', async () => {
  const flows = await import('../src/network/flows.js');
  await emptyFlows();
  const calls = [];
  let now = Math.floor(Date.now() / 864e5) * 864e5 - 864e5 + 12.5 * 36e5;   // yesterday, 12:30 UTC
  const gw = { async listFlowLogObjects(q) { calls.push(q); return demoFlowKeys({ ...q, now }); }, async getFlowLogObject({ key }) { return demoFlowFile(key); } };
  const tick = (at) => { now = at; calls.length = 0; return flows.flowTick({ gwFor: () => gw, now: at }); };
  const t0 = now, stem = `${PROD}_vpcflowlogs_us-east-1_${DEMO_FLOW_LOG}_`;
  const r = await tick(t0);
  assert.equal(r.files, 7 * 24, 'every file of the lookback');
  assert.equal(calls.length, LOOKBACK_DAYS + 1, "the newest day's folder, then one listing a day of history");
  assert.ok(calls.every((q) => q.prefix.endsWith(`/${stem}`) && !q.startAfter), 'its own files only');
  assert.equal(await tick(t0 + 6e4), null); assert.equal(calls.length, 0, 'not listed again within 5 minutes');
  const r3 = await tick(t0 + 66 * 6e4);
  assert.deepEqual([r3.files, calls.length], [1, 1], 'the one file delivered since, in one listing');
  assert.equal(calls[0].startAfter, `${calls[0].prefix}${stampOf(t0 - 2 * 36e5).slice(0, -1)}`, 'from two hours before where it got to');
});

test('per-hour Hive folders: listed an hour at a time; a short budget goes on where it stopped', async () => {
  const flows = await import('../src/network/flows.js');
  await emptyFlows();
  const items = demoAwsNetwork(PROD, 'us-east-1').items.map((i) => (i.type === 'flow-log' && i.id === DEMO_FLOW_LOG ? { ...i, data: { ...i.data, hive: true, perHour: true } } : i));
  await sync.saveNetwork({ cloud: 'aws', owner: PROD, items });
  const calls = [], now = Math.floor(Date.now() / 36e5) * 36e5 - 864e5 + 30 * 6e4;   // yesterday, half past an hour
  // two files an hour, at 5 and 35 minutes past
  const keys = (q) => {
    const m = q.prefix.match(/year=(\d{4})\/month=(\d{2})\/day=(\d{2})\/hour=(\d{2})\/[^/]*$/); if (!m) return [];
    return [5, 35].map((min) => Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], min)).filter((t) => t <= now).map((t) => ({ key: `${q.prefix}${stampOf(t)}_0abc.log.gz`, size: 1024 }));
  };
  const gw = { async listFlowLogObjects(q) { calls.push(q); return keys(q).filter((k) => !q.startAfter || k.key > q.startAfter); }, async getFlowLogObject({ key }) { return demoFlowFile(key); } };
  try {
    const r1 = await flows.flowTick({ gwFor: () => gw, now });
    const hourly = new RegExp(`^AWSLogs/aws-account-id=${PROD}/aws-service=vpcflowlogs/aws-region=us-east-1/year=\\d{4}/month=\\d{2}/day=\\d{2}/hour=\\d{2}/${PROD}_vpcflowlogs_us-east-1_${DEMO_FLOW_LOG}_$`);
    assert.ok(calls.every((q) => hourly.test(q.prefix)), calls[0]?.prefix);
    assert.equal(r1.files, 300, 'two files an hour for the lookback is more than one step reads');
    const back = new Date((await db.query('SELECT back FROM net_flow_reads WHERE flow_log = $1', [DEMO_FLOW_LOG])).rows[0].back).getTime();
    assert.ok(back > now - LOOKBACK_DAYS * 864e5, 'history part read');
    calls.length = 0;
    const r2 = await flows.flowTick({ gwFor: () => gw, now: now + 6e4 });
    assert.equal(r1.files + r2.files, 2 * 24 * LOOKBACK_DAYS, 'the rest, and nothing twice');
    assert.ok(calls.length <= 20 && calls.every((q) => !q.startAfter), `on from where it stopped: ${calls.length} listings`);
  } finally {
    await sync.saveNetwork({ cloud: 'aws', owner: PROD, items: demoAwsNetwork(PROD, 'us-east-1').items });
    await emptyFlows();
  }
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

test('an account or a project that is gone takes its networking with it', async () => {
  const conn = (await db.query('SELECT * FROM gcp_connections LIMIT 1')).rows[0];
  const item = (cloud, ownerId, connId = null) => db.query(`INSERT INTO net_items(cloud, owner, gcp_connection_id, type, native_id, name, data) VALUES ($1, $2, $3, 'network', $4, 'x', '{}')`,
    [cloud, ownerId, connId, `projects/${ownerId}/global/networks/x`]);
  const read = (cloud, ownerId) => db.query(`INSERT INTO net_reads(cloud, owner) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [cloud, ownerId]);
  const count = async (sql, p) => (await db.query(sql, p)).rows[0].n;
  // a project taken out of the connection, and an account no longer connected
  await item('gcp', 'made-up-gone', conn.id); await read('gcp', 'made-up-gone'); await read('aws', '333333333333');
  assert.equal(await sync.forgetGone(), 2);
  assert.equal(await count(`SELECT count(*)::int AS n FROM net_items WHERE owner = 'made-up-gone'`), 0);
  assert.equal(await count(`SELECT count(*)::int AS n FROM net_reads WHERE owner IN ('made-up-gone', '333333333333')`), 0);
  assert.equal(await count(`SELECT count(*)::int AS n FROM net_reads WHERE owner IN ($1, 'acme-data-stg')`, [PROD]), 2, 'what is still connected stays');
  assert.equal(await sync.forgetGone(), 0);
  // a project now in another connection: gone from this one when this one is read
  const other = (await db.query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode, wif, environment, status) VALUES ('made-up-other','project','made-up-moved','wif','{}','shared','connected') RETURNING id`)).rows[0];
  await db.query(`INSERT INTO gcp_projects(project_id, connection_id) VALUES ('made-up-moved', $1)`, [other.id]);
  await item('gcp', 'made-up-moved', conn.id);
  assert.equal(await sync.forgetGone(), 0);
  const r = await sync.readGcpNetwork(conn);
  assert.deepEqual([r.projects, r.errors], [3, 0]);
  assert.equal(await count(`SELECT count(*)::int AS n FROM net_items WHERE owner = 'made-up-moved'`), 0);
  assert.ok(await count(`SELECT count(*)::int AS n FROM net_items WHERE owner = 'acme-data-stg'`) > 0);
  await db.query('DELETE FROM gcp_connections WHERE id = $1', [other.id]);
});
