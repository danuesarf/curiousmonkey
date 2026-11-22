// A made-up estate at the size of a real one, so the Networking pages are built and tested against hundreds of
// resources and not only the two-account demo. The story: a central network account (acme-network-hub) owns 38 VPCs
// and shares their subnets with eleven app accounts through AWS RAM; each app account runs from a handful to a hundred
// network interfaces in them, a few open to the internet. A core transit gateway joins one region's VPCs, 36
// site-to-site VPNs (data centres, branches, partners, Google Cloud) and Direct Connect; a second one, peered with it,
// joins the other region's. Twenty VPC peerings reach accounts that are not connected, and every app account still
// has its default VPC. `node src/cli.js demo-large` adds the accounts to a demo workspace (AWS_MODE=demo).
// Every ID, name and address is made up; public addresses are from the documentation ranges.
import { normalizeAwsRegion } from './awsReader.js';

export const LARGE_HUB = '400000000001';
export const LARGE_ESTATE = [
  [LARGE_HUB, 'acme-network-hub', 'shared'],
  ['400000000002', 'acme-monitoring', 'shared'],
  ['400000000003', 'acme-shared-tools', 'shared'],
  ['400000000004', 'acme-security', 'production'],
  ['400000000005', 'acme-corp-apps', 'production'],
  ['400000000006', 'acme-data-eng', 'production'],
  ['400000000007', 'acme-tools-eng', 'staging'],
  ['400000000008', 'acme-kubernetes', 'production'],
  ['400000000009', 'acme-research', 'sandbox'],
  ['400000000010', 'acme-nonprod', 'staging'],
  ['400000000011', 'acme-product-eng', 'development'],
  ['400000000012', 'acme-payments', 'production'],
];
const TEAM = Object.fromEntries(LARGE_ESTATE.map(([id, name]) => [name.slice(5), id]));   // 'payments' -> its account
export const isLargeEstate = (id) => LARGE_ESTATE.some(([x]) => x === id);

// name, range, how many interfaces each app account runs in it, and what else it has: public subnets (pub), NAT
// gateways (nat), load balancers of the network account's own (lbs), flow logs (flow), a firewall, DNS resolvers, ...
const VPCS = [
  ['hub-prd-apse3', '10.64.0.0/16', { security: 24, 'corp-apps': 60, 'data-eng': 40, kubernetes: 90, payments: 70, monitoring: 10 }, { pub: true, flow: true }],
  ['hub-prd-apse1', '10.65.0.0/16', { 'corp-apps': 14, payments: 22, kubernetes: 18 }, { pub: true }],
  ['hub-nonprd-apse3', '10.80.0.0/16', { 'tools-eng': 20, nonprod: 50, 'product-eng': 30, research: 6, kubernetes: 36 }, { pub: true, flow: true }],
  ['hub-nonprd-apse1', '10.81.0.0/16', { nonprod: 10, 'product-eng': 8 }, {}],
  ['monitoring-apse3', '172.21.0.0/20', { monitoring: 16 }, { flow: true }],
  ['shared-tools-apse3', '172.21.16.0/20', { 'shared-tools': 28 }, {}],
  ['shared-tools-apse1', '172.21.32.0/21', { 'shared-tools': 6 }, {}],
  ['security-apse3', '172.21.48.0/21', { security: 12 }, { flow: true }],
  ['security-redteam-apse3', '172.21.56.0/21', { security: 3 }, { pub: true }],
  ['corp-apps-prd-apse3', '10.66.0.0/16', { 'corp-apps': 34 }, { flow: true }],
  ['data-eng-prd-apse3', '10.67.0.0/16', { 'data-eng': 26 }, {}],
  ['data-eng-nonprd-apse3', '10.82.0.0/16', { 'data-eng': 9 }, {}],
  ['tools-eng-apse3', '10.83.0.0/16', { 'tools-eng': 15 }, {}],
  ['k8s-prd-apse3', '10.68.0.0/16', { kubernetes: 80 }, { flow: true }],
  ['k8s-nonprd-apse3', '10.84.0.0/16', { kubernetes: 40 }, {}],
  ['k8s-prd-apse1', '10.69.0.0/16', { kubernetes: 20 }, {}],
  ['research-apse1', '10.85.0.0/16', { research: 7 }, { pub: true }],
  ['nonprod-apse3', '10.86.0.0/16', { nonprod: 25 }, {}],
  ['nonprod-apse1', '10.87.0.0/16', { nonprod: 6 }, {}],
  ['product-eng-apse3', '10.88.0.0/16', { 'product-eng': 18 }, {}],
  ['payments-prd-apse3', '10.70.0.0/16', { payments: 44 }, { flow: true }],
  ['payments-dr-apse1', '10.71.0.0/16', { payments: 8 }, {}],
  // the network account's own: the ways in and out, inspection, DNS, where the VPNs and Direct Connect land
  ['ingress-apse3', '10.60.0.0/20', {}, { pub: true, lbs: 4, flow: true }],
  ['egress-apse3', '10.60.16.0/20', {}, { pub: true, nat: 3, flow: true }],
  ['inspection-apse3', '10.60.32.0/20', {}, { firewall: true }],
  ['dns-apse3', '10.60.48.0/22', {}, { resolver: true }],
  ['vpn-landing-apse3', '10.60.52.0/22', {}, { clientVpn: true }],
  ['dx-landing-apse3', '10.60.56.0/22', {}, {}],
  ['shared-services-apse3', '10.60.64.0/20', {}, { endpoints: 6, service: true }],
  ['directory-apse3', '10.60.80.0/22', {}, {}],
  ['bastion-apse3', '10.60.84.0/22', {}, { pub: true, bastion: true }],
  ['ingress-apse1', '10.61.0.0/20', {}, { pub: true, lbs: 2 }],
  ['egress-apse1', '10.61.16.0/20', {}, { pub: true, nat: 2 }],
  ['inspection-apse1', '10.61.32.0/20', {}, { firewall: true }],
  ['migration-apse3', '10.62.0.0/16', {}, {}],
  ['legacy-apse3', '192.168.64.0/18', {}, { pub: true }],
  ['sandbox-apse3', '10.89.0.0/16', {}, { pub: true }],
  ['lab-apse1', '10.90.0.0/16', {}, {}],
];
// VPC peerings to accounts that are not connected: [VPC, partner number]
const PARTNER_PEERINGS = [['legacy-apse3', 1], ['hub-prd-apse3', 2], ['hub-prd-apse3', 3], ['payments-prd-apse3', 4], ['payments-prd-apse3', 5], ['data-eng-prd-apse3', 6],
  ['corp-apps-prd-apse3', 7], ['shared-services-apse3', 8], ['shared-services-apse3', 9], ['hub-nonprd-apse3', 10], ['migration-apse3', 11], ['migration-apse3', 12],
  ['k8s-prd-apse3', 13], ['monitoring-apse3', 14], ['security-apse3', 15], ['dns-apse3', 16], ['hub-prd-apse1', 17], ['payments-dr-apse1', 18], ['lab-apse1', 19], ['sandbox-apse3', 20]];
// site-to-site VPNs on the core transit gateway
const pad = (n, w = 2) => String(n).padStart(w, '0');
const SITES = ['dc-north-1', 'dc-north-2', 'dc-south-1', 'dc-south-2', 'dc-east-1', 'dc-west-1', 'dr-site-1', 'dr-site-2', 'office-hq-1', 'office-hq-2',
  ...Array.from({ length: 14 }, (_, i) => `branch-${pad(i + 1)}`), ...'abcdefgh'.split('').map((x) => `partner-${x}`), 'gcp-ha-0', 'gcp-ha-1', 'gcp-ha-2', 'gcp-ha-3'];
// what each kind of site has behind it
const siteRange = (s, i) => (/^dc-|^dr-|^office-/.test(s) ? `10.${200 + i}.0.0/16` : /^branch-/.test(s) ? `192.168.${i}.0/24` : /^partner-/.test(s) ? `100.64.${i}.0/24` : '10.128.0.0/9');

const fnv = (str) => { let h = 2166136261; for (let i = 0; i < str.length; i++) h = Math.imul(h ^ str.charCodeAt(i), 16777619); return h >>> 0; };
const hex8 = (s) => fnv(s).toString(16).padStart(8, '0');
// an AWS-looking ID made from what it is: the same thing gets the same ID in every account's read
const hid = (prefix, ...parts) => `${prefix}-0${hex8(parts.join('|'))}${hex8(`${parts.join('|')}#`)}`.slice(0, prefix.length + 18);
const tag = (name) => [{ Key: 'Name', Value: name }];
const egressAll = [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }];
const tcp = (from, to, src) => ({ IpProtocol: 'tcp', FromPort: from, ToPort: to, ...src });
const world = { IpRanges: [{ CidrIp: '0.0.0.0/0' }] };
const fromCidr = (c) => ({ IpRanges: [{ CidrIp: c }] });
const fromSg = (id, account) => ({ UserIdGroupPairs: [{ GroupId: id, UserId: account }] });
const ip2n = (ip) => ip.split('.').reduce((a, b) => a * 256 + Number(b), 0);
const n2ip = (n) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.');
// `count` equal subnets of a range, big enough for one more
const split = (cidr, count) => { const [base, len] = cidr.split('/'), bits = Math.ceil(Math.log2(count + 1)), size = 2 ** (32 - Number(len) - bits);
  return Array.from({ length: count }, (_, i) => `${n2ip(ip2n(base) + i * size)}/${Number(len) + bits}`); };
const hostIn = (cidr, k) => n2ip(ip2n(cidr.split('/')[0]) + 4 + k);   // the first four are AWS's
const naclAll = (id, vpc, subnets) => ({ NetworkAclId: id, VpcId: vpc, IsDefault: true, Associations: subnets.map((s) => ({ SubnetId: s })), Entries: [
  { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: false, CidrBlock: '0.0.0.0/0' }, { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: true, CidrBlock: '0.0.0.0/0' },
  { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: '0.0.0.0/0' }, { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: true, CidrBlock: '0.0.0.0/0' }] });
const empty = () => ({ vpcs: [], subnets: [], routeTables: [], igws: [], nats: [], sgs: [], nacls: [], enis: [], peerings: [], tgws: [], tgwAttachments: [], tgwRouteTables: [], vpns: [], cgws: [],
  endpoints: [], flowLogs: [], lbs: [], dxConnections: [], dxVifs: [], dxGateways: [], dxAssociations: [], clientVpns: [], endpointServices: [], ramShares: [], resolverEndpoints: [], firewalls: [] });

/** The whole estate in the raw shapes AWS answers with, one per account (built once per region). */
const built = new Map();
function build(region) {
  if (built.has(region)) return built.get(region);
  const HUB = LARGE_HUB, hub = empty(), member = new Map(LARGE_ESTATE.slice(1).map(([id]) => [id, empty()]));
  // public addresses, handed out in order through the three documentation ranges
  let pubN = 0;
  const pubIp = () => { const k = pubN++; return `${['198.51.100', '203.0.113', '192.0.2'][Math.floor(k / 250) % 3]}.${(k % 250) + 3}`; };
  const CORE = hid('tgw', 'core'), DR = hid('tgw', 'dr');
  const tgwOf = (name) => (name.endsWith('apse1') ? DR : CORE);
  const attach = { [CORE]: [], [DR]: [] };   // [attachment, resource type, resource, ranges]
  const vpcIds = new Map();
  hub.tgws.push({ TransitGatewayId: CORE, OwnerId: HUB, State: 'available', Options: { AmazonSideAsn: 64512, AutoAcceptSharedAttachments: 'disable' }, Tags: tag('acme-core-tgw') },
    { TransitGatewayId: DR, OwnerId: HUB, State: 'available', Options: { AmazonSideAsn: 64513, AutoAcceptSharedAttachments: 'disable' }, Tags: tag('acme-dr-tgw') });

  VPCS.forEach(([name, cidr, teams, o]) => {
    const v = hid('vpc', name); vpcIds.set(name, { id: v, cidr });
    const apps = Object.keys(teams).length > 0;
    const tiers = [...(o.pub ? ['public-a', 'public-b', 'public-c'] : []), ...(apps ? ['app-a', 'app-b', 'app-c', 'data-a', 'data-b', 'data-c'] : ['private-a', 'private-b'])];
    const ranges = split(cidr, tiers.length);
    const subs = tiers.map((t, i) => ({ SubnetId: hid('subnet', name, t), VpcId: v, CidrBlock: ranges[i], MapPublicIpOnLaunch: t.startsWith('public') && /sandbox|legacy|research/.test(name),
      AvailabilityZone: `${region}${t.slice(-1)}`, Tags: tag(`${name}-${t}`), OwnerId: HUB }));
    const pubSubs = subs.filter((s) => /public/.test(s.Tags[0].Value)), privSubs = subs.filter((s) => !pubSubs.includes(s));
    const appSubs = privSubs.filter((s) => /app|private/.test(s.Tags[0].Value)), dataSubs = privSubs.filter((s) => /data/.test(s.Tags[0].Value));
    hub.vpcs.push({ VpcId: v, CidrBlock: cidr, State: 'available', OwnerId: HUB, Tags: tag(name) });
    hub.subnets.push(...subs);
    hub.nacls.push(naclAll(hid('acl', name), v, subs.map((s) => s.SubnetId)));
    hub.sgs.push({ GroupId: hid('sg', name, 'default'), GroupName: 'default', VpcId: v, OwnerId: HUB, Description: 'default VPC security group', IpPermissions: [], IpPermissionsEgress: egressAll });
    const local = { DestinationCidrBlock: cidr, GatewayId: 'local' };
    const peerRoutes = PARTNER_PEERINGS.filter(([x]) => x === name).map(([, i]) => ({ DestinationCidrBlock: `172.30.${i}.0/24`, VpcPeeringConnectionId: hid('pcx', 'partner', i) }));
    if (o.pub) {
      const igw = hid('igw', name);
      hub.igws.push({ InternetGatewayId: igw, Attachments: [{ VpcId: v, State: 'available' }], Tags: tag(`${name}-igw`) });
      hub.routeTables.push({ RouteTableId: hid('rtb', name, 'public'), VpcId: v, Tags: tag(`${name}-public`), Associations: pubSubs.map((s) => ({ SubnetId: s.SubnetId })),
        Routes: [local, { DestinationCidrBlock: '0.0.0.0/0', GatewayId: igw }, { DestinationCidrBlock: '10.0.0.0/8', TransitGatewayId: tgwOf(name) }] });
    }
    // out through the NAT gateways of an egress VPC, or the transit gateway to one
    const nats = Array.from({ length: o.nat || 0 }, (_, k) => {
      const id = hid('nat', name, k), ip = pubIp(), s = pubSubs[k % pubSubs.length];
      hub.nats.push({ NatGatewayId: id, VpcId: v, SubnetId: s.SubnetId, State: 'available', ConnectivityType: 'public', NatGatewayAddresses: [{ PublicIp: ip }], Tags: tag(`${name}-nat-${k + 1}`) });
      hub.enis.push({ NetworkInterfaceId: hid('eni', name, 'nat', k), VpcId: v, SubnetId: s.SubnetId, PrivateIpAddress: hostIn(s.CidrBlock, 1), Association: { PublicIp: ip }, Groups: [], InterfaceType: 'nat_gateway',
        RequesterManaged: true, Description: `Interface for NAT Gateway ${id}`, OwnerId: HUB, Status: 'in-use' });
      return id;
    });
    hub.routeTables.push({ RouteTableId: hid('rtb', name, 'private'), VpcId: v, Tags: tag(`${name}-private`), Associations: [{ Main: true }, ...privSubs.map((s) => ({ SubnetId: s.SubnetId }))],
      Routes: [local, nats.length ? { DestinationCidrBlock: '0.0.0.0/0', NatGatewayId: nats[0] } : { DestinationCidrBlock: '0.0.0.0/0', TransitGatewayId: tgwOf(name) },
        ...(nats.length ? [{ DestinationCidrBlock: '10.0.0.0/8', TransitGatewayId: tgwOf(name) }] : []), ...peerRoutes] });
    const att = hid('tgw-attach', name);
    hub.tgwAttachments.push({ TransitGatewayAttachmentId: att, TransitGatewayId: tgwOf(name), TransitGatewayOwnerId: HUB, ResourceType: 'vpc', ResourceId: v, ResourceOwnerId: HUB, State: 'available', Tags: tag(name) });
    attach[tgwOf(name)].push([att, 'vpc', v, [cidr]]);
    if (o.flow) hub.flowLogs.push({ FlowLogId: hid('fl', name), ResourceId: v, FlowLogStatus: 'ACTIVE', TrafficType: 'ALL', LogDestinationType: 's3', LogDestination: 'arn:aws:s3:::acme-large-flow-logs',
      DestinationOptions: { FileFormat: 'plain-text' }, CreationTime: '2025-04-01T00:00:00.000Z', DeliverLogsStatus: 'SUCCESS' });

    // the network account's own services in it
    for (let k = 0; k < (o.lbs || 0); k++) {
      const lbName = `${name.replace(/-apse\d$/, '')}-edge-${k + 1}`, sg = hid('sg', name, 'edge'), arn = `arn:aws:elasticloadbalancing:${region}:${HUB}:loadbalancer/${k % 2 ? 'net' : 'app'}/${lbName}/${hex8(lbName)}${hex8(`${lbName}#`)}`;
      if (!k) hub.sgs.push({ GroupId: sg, GroupName: `${name}-edge`, VpcId: v, OwnerId: HUB, Description: 'Public edge', IpPermissions: [tcp(443, 443, world), tcp(80, 80, world)], IpPermissionsEgress: egressAll });
      hub.lbs.push({ LoadBalancerArn: arn, LoadBalancerName: lbName, VpcId: v, Scheme: 'internet-facing', Type: k % 2 ? 'network' : 'application', DNSName: `${lbName}.elb.example`,
        AvailabilityZones: pubSubs.map((s) => ({ SubnetId: s.SubnetId })), SecurityGroups: k % 2 ? [] : [sg], listeners: [{ Port: 443, Protocol: k % 2 ? 'TLS' : 'HTTPS' }] });
      pubSubs.forEach((s, j) => hub.enis.push({ NetworkInterfaceId: hid('eni', lbName, j), VpcId: v, SubnetId: s.SubnetId, PrivateIpAddress: hostIn(s.CidrBlock, 10 + k), Association: { PublicIp: pubIp() },
        Groups: k % 2 ? [] : [{ GroupId: sg }], InterfaceType: k % 2 ? 'network_load_balancer' : 'interface', RequesterManaged: true, RequesterId: 'amazon-elb', Description: `ELB ${k % 2 ? 'net' : 'app'}/${lbName}/${hex8(lbName)}${hex8(`${lbName}#`)}`, OwnerId: HUB, Status: 'in-use' }));
    }
    if (o.bastion) {
      const sg = hid('sg', name, 'bastion'), s = pubSubs[0];
      hub.sgs.push({ GroupId: sg, GroupName: 'bastion-ssh', VpcId: v, OwnerId: HUB, Description: 'SSH from anywhere, temporarily', IpPermissions: [tcp(22, 22, world)], IpPermissionsEgress: egressAll });
      hub.enis.push({ NetworkInterfaceId: hid('eni', name, 'bastion'), VpcId: v, SubnetId: s.SubnetId, PrivateIpAddress: hostIn(s.CidrBlock, 2), Association: { PublicIp: pubIp() }, Groups: [{ GroupId: sg }],
        InterfaceType: 'interface', Attachment: { InstanceId: hid('i', name, 'bastion') }, Description: 'bastion', OwnerId: HUB, Status: 'in-use' });
    }
    if (o.firewall) {
      hub.firewalls.push({ FirewallArn: `arn:aws:network-firewall:${region}:${HUB}:firewall/${name}`, FirewallName: name, VpcId: v, SubnetMappings: privSubs.map((s) => ({ SubnetId: s.SubnetId })),
        FirewallPolicyArn: `arn:aws:network-firewall:${region}:${HUB}:firewall-policy/egress-allowlist`, endpoints: privSubs.map((s) => hid('vpce', name, s.SubnetId)) });
      privSubs.forEach((s) => hub.enis.push({ NetworkInterfaceId: hid('eni', name, 'fw', s.SubnetId), VpcId: v, SubnetId: s.SubnetId, PrivateIpAddress: hostIn(s.CidrBlock, 3), Groups: [], InterfaceType: 'gateway_load_balancer_endpoint',
        RequesterManaged: true, Description: `VPC Endpoint Interface ${hid('vpce', name, s.SubnetId)}`, OwnerId: HUB, Status: 'in-use' }));
    }
    if (o.resolver) {
      const sg = hid('sg', name, 'dns');
      hub.sgs.push({ GroupId: sg, GroupName: 'resolver', VpcId: v, OwnerId: HUB, Description: 'DNS from the estate', IpPermissions: [{ IpProtocol: 'udp', FromPort: 53, ToPort: 53, ...fromCidr('10.0.0.0/8') }, tcp(53, 53, fromCidr('10.0.0.0/8'))], IpPermissionsEgress: egressAll });
      for (const dir of ['INBOUND', 'OUTBOUND']) hub.resolverEndpoints.push({ Id: hid('rslvr', name, dir), Name: `${dir === 'INBOUND' ? 'from' : 'to'}-on-premises`, Direction: dir, HostVPCId: v, Status: 'OPERATIONAL', SecurityGroupIds: [sg],
        ips: privSubs.map((s, j) => ({ Ip: hostIn(s.CidrBlock, 20 + j + (dir === 'INBOUND' ? 0 : 5)), SubnetId: s.SubnetId })) });
    }
    if (o.clientVpn) hub.clientVpns.push({ ClientVpnEndpointId: hid('cvpn-endpoint', name), Description: 'engineers', VpcId: v, ClientCidrBlock: '100.100.0.0/22', SplitTunnel: true, Status: { Code: 'available' },
      AuthenticationOptions: [{ Type: 'federated-authentication' }], SecurityGroupIds: [hid('sg', name, 'default')], ConnectionLogOptions: { Enabled: true },
      targets: privSubs.map((s) => ({ TargetNetworkId: s.SubnetId, Status: { Code: 'associated' } })), rules: [{ DestinationCidr: '10.0.0.0/8', AccessAll: true, Status: { Code: 'active' } }] });
    for (let k = 0; k < (o.endpoints || 0); k++) {
      const svc = ['ssm', 'ssmmessages', 'ec2messages', 'logs', 'sts', 'secretsmanager'][k], id = hid('vpce', name, svc);
      hub.endpoints.push({ VpcEndpointId: id, VpcId: v, ServiceName: `com.amazonaws.${region}.${svc}`, VpcEndpointType: 'Interface', State: 'available', SubnetIds: privSubs.map((s) => s.SubnetId), Groups: [{ GroupId: hid('sg', name, 'default') }] });
      privSubs.forEach((s, j) => hub.enis.push({ NetworkInterfaceId: hid('eni', name, svc, j), VpcId: v, SubnetId: s.SubnetId, PrivateIpAddress: hostIn(s.CidrBlock, 40 + k * 2 + j), Groups: [{ GroupId: hid('sg', name, 'default') }],
        InterfaceType: 'vpc_endpoint', RequesterManaged: true, Description: `VPC Endpoint Interface ${id}`, OwnerId: HUB, Status: 'in-use' }));
    }
    if (o.service) {
      const nlb = `arn:aws:elasticloadbalancing:${region}:${HUB}:loadbalancer/net/shared-api-pl/${hex8('shared-api-pl')}${hex8('shared-api-pl#')}`;
      hub.lbs.push({ LoadBalancerArn: nlb, LoadBalancerName: 'shared-api-pl', VpcId: v, Scheme: 'internal', Type: 'network', DNSName: 'shared-api-pl.elb.example', AvailabilityZones: privSubs.map((s) => ({ SubnetId: s.SubnetId })), SecurityGroups: [], listeners: [{ Port: 443, Protocol: 'TLS' }] });
      hub.endpointServices.push({ ServiceId: hid('vpce-svc', name), ServiceName: `com.amazonaws.vpce.${region}.${hid('vpce-svc', name)}`, AcceptanceRequired: true, ServiceState: 'Available', NetworkLoadBalancerArns: [nlb],
        connections: [[TEAM.payments, 'available'], [TEAM['corp-apps'], 'available'], ['500000000008', 'available'], ['500000000021', 'pendingAcceptance']].map(([a, state]) => ({ VpcEndpointOwner: a, VpcEndpointId: hid('vpce', 'to-shared-api', a), VpcEndpointState: state })) });
    }

    // the app accounts in it: their security groups and interfaces, seen by them and by the owner of the subnets
    if (apps) {
      hub.ramShares.push({ resourceShareArn: `arn:aws:ram:${region}:${HUB}:resource-share/${hex8(name)}`, name: `${name}-subnets`, status: 'ACTIVE', allowExternalPrincipals: false,
        resources: subs.map((s) => ({ arn: `arn:aws:ec2:${region}:${HUB}:subnet/${s.SubnetId}` })), principals: Object.keys(teams).map((t) => ({ id: TEAM[t] })) });
    }
    Object.entries(teams).forEach(([team, count], ti) => {
      const acct = TEAM[team], m = member.get(acct);
      const sg = (k, groupName, rules, description) => { const id = hid('sg', name, team, k); m.sgs.push({ GroupId: id, GroupName: groupName, VpcId: v, OwnerId: acct, Description: description, IpPermissions: rules, IpPermissionsEgress: egressAll }); return id; };
      const app = sg('app', `${team}-app`, [tcp(8080, 8080, fromCidr(cidr)), tcp(443, 443, fromCidr('10.0.0.0/8'))], 'App tier');
      const db = sg('db', `${team}-db`, [tcp(5432, 5432, fromSg(app, acct))], 'Postgres');
      sg('default', 'default', [], 'default VPC security group');
      // each app account's interfaces from its own block of addresses in each subnet (host is the number in it)
      const eni = (k, s, host, extra) => ({ NetworkInterfaceId: hid('eni', name, team, k), VpcId: v, SubnetId: s.SubnetId, PrivateIpAddress: hostIn(s.CidrBlock, 60 + ti * 40 + host),
        InterfaceType: 'interface', OwnerId: acct, Status: 'in-use', ...extra });
      for (let k = 0; k < count; k++) {
        const kind = k % 10, s = kind === 9 ? (dataSubs[k % dataSubs.length] || appSubs[0]) : appSubs[k % appSubs.length], host = Math.floor(k / privSubs.length);
        const x = kind === 9 ? eni(k, s, host, { Groups: [{ GroupId: db }], RequesterManaged: true, RequesterId: 'amazon-rds', Description: 'RDSNetworkInterface' })
          : kind === 8 ? eni(k, s, host, { Groups: [{ GroupId: app }], InterfaceType: 'lambda', RequesterManaged: true, Description: `AWS Lambda VPC ENI-${team}-worker-${k}` })
            : eni(k, s, host, { Groups: [{ GroupId: app }], Attachment: { InstanceId: hid('i', name, team, k) }, Description: `${team}-node-${k + 1}` });
        m.enis.push(x); hub.enis.push(x);
      }
      // what faces the internet: the app accounts' load balancers in the shared public subnets, and a few mistakes
      if (pubSubs.length && ['payments', 'corp-apps', 'nonprod', 'product-eng'].includes(team)) {
        const alb = sg('alb', `${team}-alb`, [tcp(443, 443, world), tcp(80, 80, world)], 'Public load balancer'), lbName = `${team}-web-${name.endsWith('apse1') ? 'apse1' : 'apse3'}`, h = `${hex8(lbName)}${hex8(`${lbName}#`)}`;
        m.lbs.push({ LoadBalancerArn: `arn:aws:elasticloadbalancing:${region}:${acct}:loadbalancer/app/${lbName}/${h}`, LoadBalancerName: lbName, VpcId: v, Scheme: 'internet-facing', Type: 'application',
          DNSName: `${lbName}.elb.example`, AvailabilityZones: pubSubs.map((s) => ({ SubnetId: s.SubnetId })), SecurityGroups: [alb], listeners: [{ Port: 443, Protocol: 'HTTPS' }, { Port: 80, Protocol: 'HTTP' }] });
        pubSubs.forEach((s, j) => { const x = eni(`alb${j}`, s, 35, { Association: { PublicIp: pubIp() }, Groups: [{ GroupId: alb }], RequesterManaged: true, RequesterId: 'amazon-elb', Description: `ELB app/${lbName}/${h}` }); m.enis.push(x); hub.enis.push(x); });
      }
      if (team === 'corp-apps' && name === 'hub-prd-apse3') {   // a Classic Load Balancer nobody moved
        const clb = sg('clb', 'legacy-portal', [tcp(443, 443, world), tcp(8443, 8443, world)], 'Old portal');
        pubSubs.slice(0, 2).forEach((s, j) => { const x = eni(`clb${j}`, s, 36, { Association: { PublicIp: pubIp() }, Groups: [{ GroupId: clb }], RequesterManaged: true, RequesterId: 'amazon-elb', Description: 'ELB legacy-portal' }); m.enis.push(x); hub.enis.push(x); });
      }
      if (team === 'research' && pubSubs.length) {   // a jump box open on SSH
        const ssh = sg('ssh', 'ssh-anywhere', [tcp(22, 22, world)], 'SSH from anywhere');
        const x = eni('jump', pubSubs[0], 37, { Association: { PublicIp: pubIp() }, Groups: [{ GroupId: ssh }], Attachment: { InstanceId: hid('i', name, team, 'jump') }, Description: 'research-jumpbox' }); m.enis.push(x); hub.enis.push(x);
      }
      if (team === 'security' && name === 'security-redteam-apse3') {   // the red team's listener, open on every port
        const any = sg('any', 'redteam-listener', [{ IpProtocol: '-1', ...world }], 'Red team exercise');
        const x = eni('listener', pubSubs[0], 38, { Association: { PublicIp: pubIp() }, Groups: [{ GroupId: any }], Attachment: { InstanceId: hid('i', name, team, 'listener') }, Description: 'redteam-listener' }); m.enis.push(x); hub.enis.push(x);
      }
      if (team === 'nonprod' && name === 'nonprod-apse3') sg('rdp', 'rdp-legacy', [tcp(3389, 3389, world)], 'Old Windows hosts');   // open, and nothing uses it
      // the shared VPC and the subnets it runs in, as the app account sees them
      if (!m.vpcs.some((x) => x.VpcId === v)) m.vpcs.push({ VpcId: v, CidrBlock: cidr, State: 'available', OwnerId: HUB, Tags: tag(name) });
      for (const s of subs) if (!m.subnets.some((x) => x.SubnetId === s.SubnetId)) m.subnets.push(s);
    });
  });

  // VPC peerings: to partners' accounts (not connected), and one between two of the network account's VPCs
  for (const [name, i] of PARTNER_PEERINGS) {
    const me = vpcIds.get(name);
    hub.peerings.push({ VpcPeeringConnectionId: hid('pcx', 'partner', i), Status: { Code: 'active' }, Tags: tag(`partner-${pad(i)}`),
      RequesterVpcInfo: { OwnerId: LARGE_HUB, VpcId: me.id, Region: region, CidrBlock: me.cidr }, AccepterVpcInfo: { OwnerId: `5000000000${pad(i)}`, VpcId: hid('vpc', 'partner', i), Region: region, CidrBlock: `172.30.${i}.0/24` } });
  }
  hub.peerings.push({ VpcPeeringConnectionId: hid('pcx', 'legacy-migration'), Status: { Code: 'active' }, Tags: tag('legacy-to-migration'),
    RequesterVpcInfo: { OwnerId: LARGE_HUB, VpcId: vpcIds.get('legacy-apse3').id, Region: region, CidrBlock: '192.168.64.0/18' }, AccepterVpcInfo: { OwnerId: LARGE_HUB, VpcId: vpcIds.get('migration-apse3').id, Region: region, CidrBlock: '10.62.0.0/16' } });

  // site-to-site VPNs on the core transit gateway; a few with a tunnel down, two with both
  SITES.forEach((s, i) => {
    const vpn = hid('vpn', s), cgw = hid('cgw', s), att = hid('tgw-attach', 'vpn', s);
    const down = (t) => (i % 13 === 7) || (t === 1 && i % 9 === 4);
    hub.cgws.push({ CustomerGatewayId: cgw, IpAddress: pubIp(), BgpAsn: String(65100 + i), State: 'available', Tags: tag(`cgw-${s}`) });
    hub.vpns.push({ VpnConnectionId: vpn, TransitGatewayId: CORE, CustomerGatewayId: cgw, State: 'available', Tags: tag(`vpn-${s}`), Options: { StaticRoutesOnly: /^branch-/.test(s) },
      VgwTelemetry: [0, 1].map((t) => ({ OutsideIpAddress: pubIp(), Status: down(t) ? 'DOWN' : 'UP', ...(down(t) ? { StatusMessage: 'IPSEC IS DOWN' } : {}) })) });
    hub.tgwAttachments.push({ TransitGatewayAttachmentId: att, TransitGatewayId: CORE, TransitGatewayOwnerId: LARGE_HUB, ResourceType: 'vpn', ResourceId: vpn, ResourceOwnerId: LARGE_HUB, State: 'available', Tags: tag(`vpn-${s}`) });
    attach[CORE].push([att, 'vpn', vpn, [siteRange(s, i)]]);
  });
  // Direct Connect: two lines at two locations, two transit interfaces each, one gateway on the core transit gateway
  const DXGW = hid('dxgw', 'acme'), dxAtt = hid('tgw-attach', 'dxgw');
  hub.dxGateways.push({ directConnectGatewayId: DXGW, directConnectGatewayName: 'acme-dxgw', amazonSideAsn: 64600, directConnectGatewayState: 'available', ownerAccount: LARGE_HUB });
  for (const [k, loc] of [['north', 'Colo North 1'], ['south', 'Colo South 1']]) {
    const con = hid('dxcon', k);
    hub.dxConnections.push({ connectionId: con, connectionName: `dx-${k}-1`, location: loc, bandwidth: '10Gbps', connectionState: 'available', ownerAccount: LARGE_HUB });
    for (const ab of ['a', 'b']) hub.dxVifs.push({ virtualInterfaceId: hid('dxvif', k, ab), virtualInterfaceName: `transit-${k}-${ab}`, virtualInterfaceType: 'transit', connectionId: con, directConnectGatewayId: DXGW,
      vlan: 300 + (ab === 'a' ? 1 : 2) + (k === 'north' ? 0 : 10), asn: 65200, amazonSideAsn: 64600, virtualInterfaceState: 'available', ownerAccount: LARGE_HUB,
      bgpPeers: [{ bgpStatus: k === 'south' && ab === 'b' ? 'down' : 'up', bgpPeerState: 'available', addressFamily: 'ipv4' }] });
  }
  hub.dxAssociations.push({ associationId: hid('dxgwassoc', 'core'), directConnectGatewayId: DXGW, directConnectGatewayOwnerAccount: LARGE_HUB, associatedGateway: { id: CORE, type: 'transitGateway', ownerAccount: LARGE_HUB, region },
    allowedPrefixesToDirectConnectGateway: [{ cidr: '10.64.0.0/12' }, { cidr: '172.21.0.0/16' }], associationState: 'associated' });
  hub.tgwAttachments.push({ TransitGatewayAttachmentId: dxAtt, TransitGatewayId: CORE, TransitGatewayOwnerId: LARGE_HUB, ResourceType: 'direct-connect-gateway', ResourceId: DXGW, ResourceOwnerId: LARGE_HUB, State: 'available' });
  attach[CORE].push([dxAtt, 'direct-connect-gateway', DXGW, ['172.16.0.0/12']]);
  // the two transit gateways peered
  const peerAtt = hid('tgw-attach', 'core-dr');
  hub.tgwAttachments.push({ TransitGatewayAttachmentId: peerAtt, TransitGatewayId: CORE, TransitGatewayOwnerId: LARGE_HUB, ResourceType: 'peering', ResourceId: DR, ResourceOwnerId: LARGE_HUB, State: 'available', Tags: tag('core-to-dr') });
  attach[CORE].push([peerAtt, 'peering', DR, VPCS.filter(([n]) => n.endsWith('apse1')).map(([, c]) => c)]);
  attach[DR].push([peerAtt, 'peering', CORE, VPCS.filter(([n]) => !n.endsWith('apse1')).map(([, c]) => c)]);
  // one route table on each: everything associated, every range propagated
  for (const [t, list] of Object.entries(attach)) hub.tgwRouteTables.push({ TransitGatewayRouteTableId: hid('tgw-rtb', t), TransitGatewayId: t, DefaultAssociationRouteTable: true, Tags: tag(t === CORE ? 'core-main' : 'dr-main'),
    associations: list.map(([a, type, id]) => ({ TransitGatewayAttachmentId: a, ResourceType: type, ResourceId: id })),
    routes: list.flatMap(([a, type, id, ranges]) => ranges.map((c) => ({ DestinationCidrBlock: c, Type: type === 'vpn' && /^192\.168\./.test(c) ? 'static' : 'propagated', State: 'active',
      TransitGatewayAttachments: [{ TransitGatewayAttachmentId: a, ResourceType: type, ResourceId: id }] }))) });

  // every app account still has its default VPC, with nothing in it
  LARGE_ESTATE.slice(1).forEach(([acct], i) => {
    const m = member.get(acct), v = hid('vpc', 'default', acct), subs = ['a', 'b', 'c'].map((z, j) => ({ SubnetId: hid('subnet', 'default', acct, z), VpcId: v, CidrBlock: `172.31.${j * 16}.0/20`, MapPublicIpOnLaunch: true,
      AvailabilityZone: `${region}${z}`, Tags: tag(`default-${z}`), OwnerId: acct })), igw = hid('igw', 'default', acct);
    m.vpcs.push({ VpcId: v, CidrBlock: '172.31.0.0/16', IsDefault: true, State: 'available', OwnerId: acct });
    m.subnets.push(...subs);
    m.igws.push({ InternetGatewayId: igw, Attachments: [{ VpcId: v, State: 'available' }] });
    m.routeTables.push({ RouteTableId: hid('rtb', 'default', acct), VpcId: v, Associations: [{ Main: true }], Routes: [{ DestinationCidrBlock: '172.31.0.0/16', GatewayId: 'local' }, { DestinationCidrBlock: '0.0.0.0/0', GatewayId: igw }] });
    m.sgs.push({ GroupId: hid('sg', 'default', acct), GroupName: 'default', VpcId: v, OwnerId: acct, Description: 'default VPC security group', IpPermissions: [{ IpProtocol: '-1', UserIdGroupPairs: [{ GroupId: hid('sg', 'default', acct), UserId: acct }] }], IpPermissionsEgress: egressAll });
    m.nacls.push(naclAll(hid('acl', 'default', acct), v, subs.map((s) => s.SubnetId)));
    // the monitoring account keeps the refusals in its default VPC, in CloudWatch Logs (not read)
    if (i === 0) m.flowLogs.push({ FlowLogId: hid('fl', 'default', acct), ResourceId: v, FlowLogStatus: 'ACTIVE', TrafficType: 'REJECT', LogDestinationType: 'cloud-watch-logs', LogDestination: `arn:aws:logs:${region}:${acct}:log-group:vpc-rejects`, CreationTime: '2025-05-01T00:00:00.000Z', DeliverLogsStatus: 'SUCCESS' });
  });
  const out = { hub, member };
  built.set(region, out);
  return out;
}

/** One account's networking in the large estate, normalised (as `listNetwork` returns it). */
export function largeAwsNetwork(accountId, region) {
  const b = build(region);
  const raw = accountId === LARGE_HUB ? b.hub : b.member.get(accountId);
  return raw ? normalizeAwsRegion(region, raw) : [];
}

/** Every account's items, each with its cloud and owner, as the analyzer gets them from the database. */
export const largeEstateItems = (region = 'ap-southeast-3') => LARGE_ESTATE.flatMap(([id]) => largeAwsNetwork(id, region).map((i) => ({ ...i, cloud: 'aws', owner: id })));
