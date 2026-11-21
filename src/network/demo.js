// Demo networking (AWS_MODE=demo), in the raw shapes the AWS and Google Cloud APIs answer with, so the same
// normalisation runs on it. Every ID and address is made up; public addresses are from the documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
//
// The story: payments-prod (111111111111) has a public web tier behind a load balancer, a bastion open to the
// internet on SSH, a database tier; it peers with data-platform-stg (222222222222) and with a vendor's account, and
// hosts a transit gateway that data-platform-stg is attached to. The transit gateway has two site-to-site VPNs to a
// Google Cloud HA VPN gateway in acme-shared-ci (the "transit" network), and one to an office whose tunnels are down.
// In Google Cloud, the transit network peers with acme-data-stg; a CI runner is open on SSH; acme-payments-prod still
// has the default network and its default firewall rules.
import { normalizeAwsRegion } from './awsReader.js';
import { normalizeGcpProject } from './gcpReader.js';

const tag = (name) => [{ Key: 'Name', Value: name }];
const all = (cidr = '0.0.0.0/0') => ({ IpRanges: [{ CidrIp: cidr }] });
const tcp = (port, src) => ({ IpProtocol: 'tcp', FromPort: port, ToPort: port, ...src });
const fromSg = (id, account) => ({ UserIdGroupPairs: [{ GroupId: id, UserId: account }] });
const egressAll = [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }];
const naclAll = (id, vpc, subnets) => ({ NetworkAclId: id, VpcId: vpc, IsDefault: true, Associations: subnets.map((s) => ({ SubnetId: s })), Entries: [
  { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: false, CidrBlock: '0.0.0.0/0' }, { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: true, CidrBlock: '0.0.0.0/0' },
  { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: '0.0.0.0/0' }, { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: true, CidrBlock: '0.0.0.0/0' }] });
const sub = (id, vpc, cidr, name, pub = false, az = 'a') => ({ SubnetId: id, VpcId: vpc, CidrBlock: cidr, MapPublicIpOnLaunch: pub, AvailabilityZone: az, Tags: tag(name) });
const rt = (id, vpc, name, subnets, routes, main = false) => ({ RouteTableId: id, VpcId: vpc, Tags: tag(name),
  Associations: [...(main ? [{ Main: true }] : []), ...subnets.map((s) => ({ SubnetId: s }))], Routes: [{ DestinationCidrBlock: '10.0.0.0/8', GatewayId: 'local' }, ...routes] });
const defaultVpc = (acct, region, n) => {
  const vpc = `vpc-0def${n}`, subs = [`subnet-0def${n}a`, `subnet-0def${n}b`];
  return {
    vpcs: [{ VpcId: vpc, CidrBlock: '172.31.0.0/16', IsDefault: true, State: 'available', OwnerId: acct }],
    subnets: [sub(subs[0], vpc, '172.31.0.0/20', 'default-a', true, `${region}a`), sub(subs[1], vpc, '172.31.16.0/20', 'default-b', true, `${region}b`)],
    routeTables: [rt(`rtb-0def${n}`, vpc, 'default', [], [{ DestinationCidrBlock: '0.0.0.0/0', GatewayId: `igw-0def${n}` }], true)],
    igws: [{ InternetGatewayId: `igw-0def${n}`, Attachments: [{ VpcId: vpc, State: 'available' }] }],
    sgs: [{ GroupId: `sg-0def${n}`, GroupName: 'default', VpcId: vpc, OwnerId: acct, Description: 'default VPC security group', IpPermissions: [{ IpProtocol: '-1', UserIdGroupPairs: [{ GroupId: `sg-0def${n}`, UserId: acct }] }], IpPermissionsEgress: egressAll }],
    nacls: [naclAll(`acl-0def${n}`, vpc, subs)],
  };
};
const merge = (...parts) => { const out = {}; for (const p of parts) for (const [k, v] of Object.entries(p)) out[k] = [...(out[k] || []), ...v]; return out; };

const PROD = '111111111111', DATA = '222222222222', VENDOR = '999999999999';
export const DEMO_TGW = 'tgw-0a1b2c3d4e5f60001';

function prod(region) {
  const v = 'vpc-0a1b2c3d4e5f60010', [pa, pb, app, db] = ['subnet-0a10000000000pa', 'subnet-0a10000000000pb', 'subnet-0a1000000000app', 'subnet-0a10000000000db'];
  return merge(defaultVpc(PROD, region, 1), {
    vpcs: [{ VpcId: v, CidrBlock: '10.10.0.0/16', State: 'available', OwnerId: PROD, Tags: tag('prod-core') }],
    subnets: [sub(pa, v, '10.10.0.0/24', 'public-a', true, `${region}a`), sub(pb, v, '10.10.1.0/24', 'public-b', true, `${region}b`), sub(app, v, '10.10.10.0/24', 'app-a', false, `${region}a`), sub(db, v, '10.10.20.0/24', 'db-a', false, `${region}a`)],
    routeTables: [
      rt('rtb-0a1000000000public', v, 'public', [pa, pb], [{ DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'igw-0a1000000000000001' }, { DestinationCidrBlock: '10.20.0.0/16', VpcPeeringConnectionId: 'pcx-0a10000000000data' }]),
      rt('rtb-0a100000000private', v, 'private', [app, db], [{ DestinationCidrBlock: '0.0.0.0/0', NatGatewayId: 'nat-0a10000000000001' }, { DestinationCidrBlock: '10.20.0.0/16', VpcPeeringConnectionId: 'pcx-0a10000000000data' },
        { DestinationCidrBlock: '10.128.0.0/9', TransitGatewayId: DEMO_TGW }, { DestinationCidrBlock: '172.20.0.0/16', VpcPeeringConnectionId: 'pcx-0a100000000vendor' }, { DestinationCidrBlock: '192.168.0.0/16', TransitGatewayId: DEMO_TGW }], true),
    ],
    igws: [{ InternetGatewayId: 'igw-0a1000000000000001', Attachments: [{ VpcId: v, State: 'available' }], Tags: tag('prod-igw') }],
    nats: [{ NatGatewayId: 'nat-0a10000000000001', VpcId: v, SubnetId: pa, State: 'available', ConnectivityType: 'public', NatGatewayAddresses: [{ PublicIp: '203.0.113.10' }], Tags: tag('prod-nat-a') }],
    sgs: [
      { GroupId: 'sg-0a1000000000000alb', GroupName: 'alb-public', VpcId: v, OwnerId: PROD, Description: 'Public load balancer', IpPermissions: [tcp(443, all()), tcp(80, all())], IpPermissionsEgress: egressAll },
      { GroupId: 'sg-0a1000000000000app', GroupName: 'app', VpcId: v, OwnerId: PROD, Description: 'App tier', IpPermissions: [tcp(8080, fromSg('sg-0a1000000000000alb', PROD))], IpPermissionsEgress: egressAll },
      { GroupId: 'sg-0a10000000000000db', GroupName: 'db', VpcId: v, OwnerId: PROD, Description: 'Postgres', IpPermissions: [tcp(5432, fromSg('sg-0a1000000000000app', PROD)), tcp(5432, all('10.20.0.0/16'))], IpPermissionsEgress: egressAll },
      { GroupId: 'sg-0a10000000000bastn', GroupName: 'bastion', VpcId: v, OwnerId: PROD, Description: 'SSH bastion', IpPermissions: [tcp(22, all())], IpPermissionsEgress: egressAll },
      { GroupId: 'sg-0a10000000000legcy', GroupName: 'legacy-rdp', VpcId: v, OwnerId: PROD, Description: 'Old Windows jump host', IpPermissions: [tcp(3389, all())], IpPermissionsEgress: egressAll },
      { GroupId: 'sg-0a10000000000dflt', GroupName: 'default', VpcId: v, OwnerId: PROD, Description: 'default VPC security group', IpPermissions: [{ IpProtocol: '-1', UserIdGroupPairs: [{ GroupId: 'sg-0a10000000000dflt', UserId: PROD }] }], IpPermissionsEgress: egressAll },
    ],
    nacls: [naclAll('acl-0a10000000000001', v, [pa, pb, app, db])],
    peerings: [
      { VpcPeeringConnectionId: 'pcx-0a10000000000data', Status: { Code: 'active' }, Tags: tag('prod-to-data'),
        RequesterVpcInfo: { OwnerId: PROD, VpcId: v, Region: region, CidrBlock: '10.10.0.0/16' }, AccepterVpcInfo: { OwnerId: DATA, VpcId: 'vpc-0b2b2c3d4e5f60020', Region: region, CidrBlock: '10.20.0.0/16' } },
      { VpcPeeringConnectionId: 'pcx-0a100000000vendor', Status: { Code: 'active' }, Tags: tag('vendor-analytics'),
        RequesterVpcInfo: { OwnerId: VENDOR, VpcId: 'vpc-0c9c9c9c9c9c90099', Region: region, CidrBlock: '172.20.0.0/16' }, AccepterVpcInfo: { OwnerId: PROD, VpcId: v, Region: region, CidrBlock: '10.10.0.0/16' } },
    ],
    tgws: [{ TransitGatewayId: DEMO_TGW, OwnerId: PROD, State: 'available', Options: { AmazonSideAsn: 64512, AutoAcceptSharedAttachments: 'disable' }, Tags: tag('hub') }],
    tgwAttachments: [
      { TransitGatewayAttachmentId: 'tgw-attach-0a1000000prod', TransitGatewayId: DEMO_TGW, TransitGatewayOwnerId: PROD, ResourceType: 'vpc', ResourceId: v, ResourceOwnerId: PROD, State: 'available', Tags: tag('prod-core') },
      { TransitGatewayAttachmentId: 'tgw-attach-0a1000000data', TransitGatewayId: DEMO_TGW, TransitGatewayOwnerId: PROD, ResourceType: 'vpc', ResourceId: 'vpc-0b2b2c3d4e5f60020', ResourceOwnerId: DATA, State: 'available', Tags: tag('data-platform') },
      { TransitGatewayAttachmentId: 'tgw-attach-0a1000000vpn0', TransitGatewayId: DEMO_TGW, TransitGatewayOwnerId: PROD, ResourceType: 'vpn', ResourceId: 'vpn-0a1000000000gcp0', ResourceOwnerId: PROD, State: 'available' },
      { TransitGatewayAttachmentId: 'tgw-attach-0a1000000vpn1', TransitGatewayId: DEMO_TGW, TransitGatewayOwnerId: PROD, ResourceType: 'vpn', ResourceId: 'vpn-0a1000000000gcp1', ResourceOwnerId: PROD, State: 'available' },
      { TransitGatewayAttachmentId: 'tgw-attach-0a100000office', TransitGatewayId: DEMO_TGW, TransitGatewayOwnerId: PROD, ResourceType: 'vpn', ResourceId: 'vpn-0a10000000office', ResourceOwnerId: PROD, State: 'available' },
    ],
    vpns: [
      { VpnConnectionId: 'vpn-0a1000000000gcp0', TransitGatewayId: DEMO_TGW, CustomerGatewayId: 'cgw-0a1000000000gcp0', State: 'available', Tags: tag('gcp-ha-0'),
        VgwTelemetry: [{ OutsideIpAddress: '203.0.113.50', Status: 'UP' }, { OutsideIpAddress: '203.0.113.51', Status: 'UP' }] },
      { VpnConnectionId: 'vpn-0a1000000000gcp1', TransitGatewayId: DEMO_TGW, CustomerGatewayId: 'cgw-0a1000000000gcp1', State: 'available', Tags: tag('gcp-ha-1'),
        VgwTelemetry: [{ OutsideIpAddress: '203.0.113.52', Status: 'UP' }, { OutsideIpAddress: '203.0.113.53', Status: 'DOWN', StatusMessage: 'IPSEC IS DOWN' }] },
      { VpnConnectionId: 'vpn-0a10000000office', TransitGatewayId: DEMO_TGW, CustomerGatewayId: 'cgw-0a1000000office', State: 'available', Tags: tag('office-hq'), Options: { StaticRoutesOnly: true },
        VgwTelemetry: [{ OutsideIpAddress: '203.0.113.60', Status: 'DOWN', StatusMessage: 'IPSEC IS DOWN' }, { OutsideIpAddress: '203.0.113.61', Status: 'DOWN', StatusMessage: 'IPSEC IS DOWN' }] },
    ],
    cgws: [{ CustomerGatewayId: 'cgw-0a1000000000gcp0', IpAddress: '192.0.2.10', BgpAsn: '64514', State: 'available', Tags: tag('gcp-to-aws-if0') },
      { CustomerGatewayId: 'cgw-0a1000000000gcp1', IpAddress: '192.0.2.11', BgpAsn: '64514', State: 'available', Tags: tag('gcp-to-aws-if1') },
      { CustomerGatewayId: 'cgw-0a1000000office', IpAddress: '198.51.100.200', BgpAsn: '65000', State: 'available', Tags: tag('office-hq-firewall') }],
    endpoints: [{ VpcEndpointId: 'vpce-0a10000000000s3', VpcId: v, ServiceName: `com.amazonaws.${region}.s3`, VpcEndpointType: 'Gateway', State: 'available', RouteTableIds: ['rtb-0a100000000private'],
      PolicyDocument: JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' }] }) }],
    enis: [
      { NetworkInterfaceId: 'eni-0a100000000bastion', VpcId: v, SubnetId: pa, PrivateIpAddress: '10.10.0.20', Association: { PublicIp: '198.51.100.20' }, Groups: [{ GroupId: 'sg-0a10000000000bastn' }],
        InterfaceType: 'interface', Attachment: { InstanceId: 'i-0a10000000bastion' }, Description: 'bastion', Status: 'in-use' },
      { NetworkInterfaceId: 'eni-0a1000000000alb0a', VpcId: v, SubnetId: pa, PrivateIpAddress: '10.10.0.40', Association: { PublicIp: '198.51.100.30' }, Groups: [{ GroupId: 'sg-0a1000000000000alb' }],
        InterfaceType: 'interface', RequesterManaged: true, RequesterId: 'amazon-elb', Description: 'ELB app/payments-web/0a1b2c3d4e5f6000', Status: 'in-use' },
      { NetworkInterfaceId: 'eni-0a1000000000app01', VpcId: v, SubnetId: app, PrivateIpAddress: '10.10.10.15', Groups: [{ GroupId: 'sg-0a1000000000000app' }], InterfaceType: 'interface', Attachment: { InstanceId: 'i-0a1000000000app01' }, Description: 'payments-api', Status: 'in-use' },
      { NetworkInterfaceId: 'eni-0a10000000000db01', VpcId: v, SubnetId: db, PrivateIpAddress: '10.10.20.10', Groups: [{ GroupId: 'sg-0a10000000000000db' }], InterfaceType: 'interface', RequesterManaged: true, RequesterId: 'amazon-rds', Description: 'RDSNetworkInterface', Status: 'in-use' },
      { NetworkInterfaceId: 'eni-0a100000000natgw', VpcId: v, SubnetId: pa, PrivateIpAddress: '10.10.0.5', Association: { PublicIp: '203.0.113.10' }, Groups: [], InterfaceType: 'nat_gateway', RequesterManaged: true, Description: 'Interface for NAT Gateway nat-0a10000000000001', Status: 'in-use' },
    ],
    flowLogs: [{ FlowLogId: 'fl-0a10000000000001', ResourceId: v, FlowLogStatus: 'ACTIVE', TrafficType: 'ALL', LogDestinationType: 's3' }],
    lbs: [{ LoadBalancerArn: `arn:aws:elasticloadbalancing:${region}:${PROD}:loadbalancer/app/payments-web/0a1b2c3d4e5f6000`, LoadBalancerName: 'payments-web', VpcId: v, Scheme: 'internet-facing', Type: 'application',
      DNSName: 'payments-web-123456.elb.example', AvailabilityZones: [{ SubnetId: pa }, { SubnetId: pb }], SecurityGroups: ['sg-0a1000000000000alb'], listeners: [{ Port: 443, Protocol: 'HTTPS' }, { Port: 80, Protocol: 'HTTP' }] }],
  });
}

function data(region) {
  const v = 'vpc-0b2b2c3d4e5f60020', [pub, a, b] = ['subnet-0b20000000000pub', 'subnet-0b200000000data', 'subnet-0b200000000datb'];
  return merge(defaultVpc(DATA, region, 2), {
    vpcs: [{ VpcId: v, CidrBlock: '10.20.0.0/16', State: 'available', OwnerId: DATA, Tags: tag('data-platform') }],
    subnets: [sub(pub, v, '10.20.0.0/24', 'egress', false, `${region}a`), sub(a, v, '10.20.1.0/24', 'data-a', false, `${region}a`), sub(b, v, '10.20.2.0/24', 'data-b', false, `${region}b`)],
    routeTables: [
      rt('rtb-0b200000000egress', v, 'egress', [pub], [{ DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'igw-0b2000000000000001' }]),
      rt('rtb-0b20000000000data', v, 'data', [a, b], [{ DestinationCidrBlock: '0.0.0.0/0', NatGatewayId: 'nat-0b20000000000001' }, { DestinationCidrBlock: '10.10.0.0/16', VpcPeeringConnectionId: 'pcx-0a10000000000data' },
        { DestinationCidrBlock: '10.128.0.0/9', TransitGatewayId: DEMO_TGW }], true),
    ],
    igws: [{ InternetGatewayId: 'igw-0b2000000000000001', Attachments: [{ VpcId: v, State: 'available' }], Tags: tag('data-igw') }],
    nats: [{ NatGatewayId: 'nat-0b20000000000001', VpcId: v, SubnetId: pub, State: 'available', ConnectivityType: 'public', NatGatewayAddresses: [{ PublicIp: '203.0.113.20' }], Tags: tag('data-nat') }],
    sgs: [
      { GroupId: 'sg-0b200000000000redis', GroupName: 'redis-cache', VpcId: v, OwnerId: DATA, Description: 'Redis for the ETL jobs', IpPermissions: [tcp(6379, all())], IpPermissionsEgress: egressAll },
      { GroupId: 'sg-0b20000000000000etl', GroupName: 'etl-workers', VpcId: v, OwnerId: DATA, Description: 'ETL workers', IpPermissions: [{ IpProtocol: 'tcp', FromPort: 0, ToPort: 65535, IpRanges: [{ CidrIp: '10.0.0.0/8' }] }], IpPermissionsEgress: egressAll },
      { GroupId: 'sg-0b2000000000000dflt', GroupName: 'default', VpcId: v, OwnerId: DATA, Description: 'default VPC security group', IpPermissions: [], IpPermissionsEgress: egressAll },
    ],
    nacls: [naclAll('acl-0b20000000000001', v, [pub, a, b])],
    peerings: [{ VpcPeeringConnectionId: 'pcx-0a10000000000data', Status: { Code: 'active' }, Tags: tag('prod-to-data'),
      RequesterVpcInfo: { OwnerId: PROD, VpcId: 'vpc-0a1b2c3d4e5f60010', Region: region, CidrBlock: '10.10.0.0/16' }, AccepterVpcInfo: { OwnerId: DATA, VpcId: v, Region: region, CidrBlock: '10.20.0.0/16' } }],
    tgwAttachments: [{ TransitGatewayAttachmentId: 'tgw-attach-0a1000000data', TransitGatewayId: DEMO_TGW, TransitGatewayOwnerId: PROD, ResourceType: 'vpc', ResourceId: v, ResourceOwnerId: DATA, State: 'available', Tags: tag('data-platform') }],
    enis: [
      { NetworkInterfaceId: 'eni-0b20000000redis01', VpcId: v, SubnetId: a, PrivateIpAddress: '10.20.1.30', Groups: [{ GroupId: 'sg-0b200000000000redis' }], InterfaceType: 'interface', RequesterManaged: true, RequesterId: 'amazon-elasticache', Description: 'ElastiCache redis-etl-0001', Status: 'in-use' },
      { NetworkInterfaceId: 'eni-0b200000000etl001', VpcId: v, SubnetId: a, PrivateIpAddress: '10.20.1.50', Groups: [{ GroupId: 'sg-0b20000000000000etl' }], InterfaceType: 'interface', Attachment: { InstanceId: 'i-0b2000000000etl01' }, Description: 'etl-worker-1', Status: 'in-use' },
    ],
    firewalls: [],
  });
}

/** One AWS account's networking in its first region, normalised. */
export function demoAwsNetwork(accountId, region) {
  if (process.env.DEMO_NETWORK_DENIED === '1') return { items: [], skipped: ['ec2:DescribeVpcs'] };
  const raw = accountId === PROD ? prod(region) : accountId === DATA ? data(region) : defaultVpc(accountId, region, 9);
  return { items: normalizeAwsRegion(region, raw), skipped: [] };
}

// ---------------------------------------------------------------- Google Cloud
const net = (p, n) => `https://www.googleapis.com/compute/v1/projects/${p}/global/networks/${n}`;
const reg = (p, r) => `https://www.googleapis.com/compute/v1/projects/${p}/regions/${r}`;
const fw = (p, n, name, rule, src, extra = {}) => ({ name, network: net(p, n), direction: 'INGRESS', priority: 1000, allowed: [rule], sourceRanges: src, ...extra });
const R = 'us-central1';
const GCP = {
  'acme-shared-ci': {
    networks: [{ name: 'transit', autoCreateSubnetworks: false, routingConfig: { routingMode: 'GLOBAL' }, peerings: [{ name: 'transit-to-data', network: net('acme-data-stg', 'data-vpc'), state: 'ACTIVE', exportCustomRoutes: true, importCustomRoutes: true }] },
      { name: 'ci', autoCreateSubnetworks: false, routingConfig: { routingMode: 'REGIONAL' } }],
    subnetworks: [{ name: 'transit-us', network: net('acme-shared-ci', 'transit'), region: reg('acme-shared-ci', R), ipCidrRange: '10.200.0.0/24', privateIpGoogleAccess: true, logConfig: { enable: true } },
      { name: 'ci-runners', network: net('acme-shared-ci', 'ci'), region: reg('acme-shared-ci', R), ipCidrRange: '10.210.0.0/24', privateIpGoogleAccess: false }],
    firewalls: [fw('acme-shared-ci', 'ci', 'allow-ssh-anywhere', { IPProtocol: 'tcp', ports: ['22'] }, ['0.0.0.0/0'], { targetTags: ['ssh'] }),
      fw('acme-shared-ci', 'transit', 'allow-from-aws', { IPProtocol: 'all' }, ['10.10.0.0/16', '10.20.0.0/16']),
      fw('acme-shared-ci', 'ci', 'allow-iap-ssh', { IPProtocol: 'tcp', ports: ['22'] }, ['35.235.240.0/20'], { logConfig: { enable: true } })],
    routers: [{ name: 'transit-router', network: net('acme-shared-ci', 'transit'), region: reg('acme-shared-ci', R), bgp: { asn: 64514 },
      bgpPeers: [0, 1, 2, 3].map((i) => ({ name: `aws-peer-${i}`, peerIpAddress: `169.254.10.${i * 4 + 1}`, peerAsn: 64512, interfaceName: `if-tunnel-${i}` })) },
    { name: 'ci-router', network: net('acme-shared-ci', 'ci'), region: reg('acme-shared-ci', R), nats: [{ name: 'ci-nat', sourceSubnetworkIpRangesToNat: 'ALL_SUBNETWORKS_ALL_IP_RANGES', natIpAllocateOption: 'AUTO_ONLY' }] }],
    vpnGateways: [{ name: 'to-aws', network: net('acme-shared-ci', 'transit'), region: reg('acme-shared-ci', R), vpnInterfaces: [{ id: 0, ipAddress: '192.0.2.10' }, { id: 1, ipAddress: '192.0.2.11' }] }],
    externalVpnGateways: [{ name: 'aws-hub', redundancyType: 'FOUR_IPS_REDUNDANCY', interfaces: ['203.0.113.50', '203.0.113.51', '203.0.113.52', '203.0.113.53'].map((ip, id) => ({ id, ipAddress: ip })) }],
    vpnTunnels: ['203.0.113.50', '203.0.113.51', '203.0.113.52', '203.0.113.53'].map((ip, i) => ({ name: `aws-tunnel-${i}`, region: reg('acme-shared-ci', R), peerIp: ip,
      vpnGateway: `${reg('acme-shared-ci', R)}/vpnGateways/to-aws`, peerExternalGateway: 'https://www.googleapis.com/compute/v1/projects/acme-shared-ci/global/externalVpnGateways/aws-hub',
      router: `${reg('acme-shared-ci', R)}/routers/transit-router`, status: i === 3 ? 'NO_INCOMING_PACKETS' : 'ESTABLISHED', detailedStatus: i === 3 ? 'No incoming packets from peer.' : 'Tunnel is up and running.', ikeVersion: 2 })),
    instances: [{ name: 'ci-runner-1', zone: `${reg('acme-shared-ci', R).replace('regions', 'zones')}-a`, status: 'RUNNING', tags: { items: ['ssh', 'ci'] },
      serviceAccounts: [{ email: 'deployer@acme-shared-ci.iam.gserviceaccount.com' }], networkInterfaces: [{ network: net('acme-shared-ci', 'ci'), subnetwork: `${reg('acme-shared-ci', R)}/subnetworks/ci-runners`, networkIP: '10.210.0.5', accessConfigs: [{ natIP: '198.51.100.77' }] }] }],
    addresses: [{ name: 'ci-runner-ip', address: '198.51.100.77', addressType: 'EXTERNAL', status: 'IN_USE', region: reg('acme-shared-ci', R), users: ['ci-runner-1'] }],
  },
  'acme-data-stg': {
    networks: [{ name: 'data-vpc', autoCreateSubnetworks: false, routingConfig: { routingMode: 'GLOBAL' },
      peerings: [{ name: 'data-to-transit', network: net('acme-shared-ci', 'transit'), state: 'ACTIVE', importCustomRoutes: true }, { name: 'partner-feed', network: net('partner-data-net-4821', 'partner-vpc'), state: 'ACTIVE' }] }],
    subnetworks: [{ name: 'lake', network: net('acme-data-stg', 'data-vpc'), region: reg('acme-data-stg', R), ipCidrRange: '10.128.0.0/20', privateIpGoogleAccess: true },
      { name: 'dataflow', network: net('acme-data-stg', 'data-vpc'), region: reg('acme-data-stg', R), ipCidrRange: '10.128.16.0/20', privateIpGoogleAccess: true, logConfig: { enable: true } }],
    firewalls: [fw('acme-data-stg', 'data-vpc', 'allow-internal', { IPProtocol: 'all' }, ['10.0.0.0/8']),
      fw('acme-data-stg', 'data-vpc', 'allow-redis-anywhere', { IPProtocol: 'tcp', ports: ['6379'] }, ['0.0.0.0/0'])],
    routers: [{ name: 'data-router', network: net('acme-data-stg', 'data-vpc'), region: reg('acme-data-stg', R), nats: [{ name: 'data-nat', sourceSubnetworkIpRangesToNat: 'ALL_SUBNETWORKS_ALL_IP_RANGES', natIpAllocateOption: 'AUTO_ONLY', logConfig: { enable: true } }] }],
    instances: [{ name: 'etl-1', zone: `${reg('acme-data-stg', R).replace('regions', 'zones')}-b`, status: 'RUNNING', tags: { items: ['etl'] }, serviceAccounts: [{ email: 'etl-runner@acme-data-stg.iam.gserviceaccount.com' }],
      networkInterfaces: [{ network: net('acme-data-stg', 'data-vpc'), subnetwork: `${reg('acme-data-stg', R)}/subnetworks/lake`, networkIP: '10.128.0.12' }] }],
  },
  'acme-payments-prod': {
    networks: [{ name: 'default', autoCreateSubnetworks: true, routingConfig: { routingMode: 'REGIONAL' } }],
    subnetworks: [{ name: 'default', network: net('acme-payments-prod', 'default'), region: reg('acme-payments-prod', R), ipCidrRange: '10.130.0.0/20' },
      { name: 'default', network: net('acme-payments-prod', 'default'), region: reg('acme-payments-prod', 'asia-southeast2'), ipCidrRange: '10.184.0.0/20' }],
    firewalls: [fw('acme-payments-prod', 'default', 'default-allow-ssh', { IPProtocol: 'tcp', ports: ['22'] }, ['0.0.0.0/0'], { priority: 65534 }),
      fw('acme-payments-prod', 'default', 'default-allow-rdp', { IPProtocol: 'tcp', ports: ['3389'] }, ['0.0.0.0/0'], { priority: 65534 }),
      fw('acme-payments-prod', 'default', 'default-allow-icmp', { IPProtocol: 'icmp' }, ['0.0.0.0/0'], { priority: 65534 }),
      fw('acme-payments-prod', 'default', 'default-allow-internal', { IPProtocol: 'all' }, ['10.128.0.0/9'], { priority: 65534 }),
      fw('acme-payments-prod', 'default', 'allow-https-lb', { IPProtocol: 'tcp', ports: ['443'] }, ['130.211.0.0/22', '35.191.0.0/16'], { targetTags: ['web'] })],
    routes: [{ name: 'default-route-internet', network: net('acme-payments-prod', 'default'), destRange: '0.0.0.0/0', priority: 1000, nextHopGateway: 'https://www.googleapis.com/compute/v1/projects/acme-payments-prod/global/gateways/default-internet-gateway' }],
    instances: [{ name: 'payments-api-1', zone: `${reg('acme-payments-prod', R).replace('regions', 'zones')}-a`, status: 'RUNNING', tags: { items: ['web'] },
      serviceAccounts: [{ email: 'payments-api@acme-payments-prod.iam.gserviceaccount.com' }],
      networkInterfaces: [{ network: net('acme-payments-prod', 'default'), subnetwork: `${reg('acme-payments-prod', R)}/subnetworks/default`, networkIP: '10.130.0.8', accessConfigs: [{ natIP: '198.51.100.90' }] }] }],
    forwardingRules: [{ name: 'payments-lb', IPAddress: '198.51.100.91', IPProtocol: 'TCP', portRange: '443-443', loadBalancingScheme: 'EXTERNAL_MANAGED', target: 'https://www.googleapis.com/compute/v1/projects/acme-payments-prod/global/targetHttpsProxies/payments' }],
  },
};

/** One project's networking, raw, as the real gateway's network() answers. */
export function demoGcpNetwork(projectId) {
  if (process.env.DEMO_GCP_NETWORK_DENIED === '1') return { raw: {}, skipped: ['networks'] };
  return { raw: GCP[projectId] || {}, skipped: [] };
}
export const demoGcpNormalized = (projectId) => normalizeGcpProject(projectId, GCP[projectId] || {});
