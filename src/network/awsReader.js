// Reading AWS networking through the read-only scanner role: everything that decides what can reach what. VPCs,
// subnets, route tables, internet, egress-only and NAT gateways, security groups, network ACLs, VPC peering, transit
// gateways and their attachments, site-to-site VPNs (customer and virtual private gateways), VPC endpoints, network
// interfaces (who sits where, with which public IP and groups), flow logs, Network Firewall and load balancers;
// Direct Connect (connections, virtual interfaces, Direct Connect gateways and what they are associated with),
// transit gateway route tables, Client VPN endpoints, PrivateLink endpoint services and who connects to them, managed
// prefix lists and Route 53 Resolver endpoints and forwarding rules; the subnets this account shares through AWS RAM
// (a central network account sharing a VPC with member accounts) and with whom. A member account needs nothing
// extra: the VPCs and subnets shared into it come back from DescribeVpcs and DescribeSubnets with the owner's ID.
// Each call that is denied is skipped and named, so one missing permission does not lose the rest.
import { EC2Client, DescribeVpcsCommand, DescribeSubnetsCommand, DescribeRouteTablesCommand, DescribeInternetGatewaysCommand, DescribeEgressOnlyInternetGatewaysCommand,
  DescribeNatGatewaysCommand, DescribeSecurityGroupsCommand, DescribeNetworkAclsCommand, DescribeVpcPeeringConnectionsCommand, DescribeTransitGatewaysCommand,
  DescribeTransitGatewayAttachmentsCommand, DescribeVpnConnectionsCommand, DescribeCustomerGatewaysCommand, DescribeVpnGatewaysCommand, DescribeVpcEndpointsCommand,
  DescribeNetworkInterfacesCommand, DescribeFlowLogsCommand, DescribeClientVpnEndpointsCommand, DescribeClientVpnTargetNetworksCommand, DescribeClientVpnAuthorizationRulesCommand,
  DescribeTransitGatewayRouteTablesCommand, SearchTransitGatewayRoutesCommand, GetTransitGatewayRouteTableAssociationsCommand, DescribeVpcEndpointServiceConfigurationsCommand,
  DescribeVpcEndpointConnectionsCommand, DescribeManagedPrefixListsCommand, GetManagedPrefixListEntriesCommand } from '@aws-sdk/client-ec2';
import { DirectConnectClient, DescribeConnectionsCommand, DescribeVirtualInterfacesCommand, DescribeDirectConnectGatewaysCommand, DescribeDirectConnectGatewayAssociationsCommand } from '@aws-sdk/client-direct-connect';
import { Route53ResolverClient, ListResolverEndpointsCommand, ListResolverEndpointIpAddressesCommand, ListResolverRulesCommand, ListResolverRuleAssociationsCommand } from '@aws-sdk/client-route53resolver';
import { NetworkFirewallClient, ListFirewallsCommand, DescribeFirewallCommand } from '@aws-sdk/client-network-firewall';
import { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand, DescribeListenersCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { RAMClient, GetResourceSharesCommand, ListResourcesCommand, ListPrincipalsCommand } from '@aws-sdk/client-ram';
import { bump } from '../telemetry.js';

const DENIED = /AccessDenied|UnauthorizedOperation|not authorized|AuthorizationError|OptInRequired/i;
const nameTag = (tags) => (tags || []).find((t) => t.Key === 'Name')?.Value || null;
const proto = (p) => (p === '-1' ? 'all' : p === '6' ? 'tcp' : p === '17' ? 'udp' : p === '1' ? 'icmp' : p === '58' ? 'icmpv6' : String(p));

/** A security group rule, flattened: protocol, ports, and every source or destination it names. */
export const sgRule = (p) => ({
  proto: proto(p.IpProtocol), from: p.FromPort ?? null, to: p.ToPort ?? null,
  cidrs: (p.IpRanges || []).map((r) => r.CidrIp), ipv6: (p.Ipv6Ranges || []).map((r) => r.CidrIpv6),
  groups: (p.UserIdGroupPairs || []).map((g) => ({ id: g.GroupId, account: g.UserId || null, peering: g.VpcPeeringConnectionId || null })),
  prefixLists: (p.PrefixListIds || []).map((x) => x.PrefixListId),
  descriptions: [...(p.IpRanges || []), ...(p.Ipv6Ranges || []), ...(p.UserIdGroupPairs || [])].map((r) => r.Description).filter(Boolean).slice(0, 4),
});

/** The items of one region, already normalised: [{ type, id, name, vpc, region, data }]. */
export function normalizeAwsRegion(region, r) {
  const out = [];
  const add = (type, id, name, vpc, data) => out.push({ type, id, name: name || id, vpc: vpc || null, region, data });
  for (const v of r.vpcs || []) add('vpc', v.VpcId, nameTag(v.Tags), v.VpcId, { cidrs: (v.CidrBlockAssociationSet || [{ CidrBlock: v.CidrBlock }]).map((c) => c.CidrBlock).filter(Boolean),
    ipv6: (v.Ipv6CidrBlockAssociationSet || []).map((c) => c.Ipv6CidrBlock).filter(Boolean), isDefault: !!v.IsDefault, state: v.State || null, owner: v.OwnerId || null });
  for (const s of r.subnets || []) add('subnet', s.SubnetId, nameTag(s.Tags), s.VpcId, { cidr: s.CidrBlock, ipv6: (s.Ipv6CidrBlockAssociationSet || []).map((c) => c.Ipv6CidrBlock),
    az: s.AvailabilityZone || null, mapPublicIp: !!s.MapPublicIpOnLaunch, owner: s.OwnerId || null });
  for (const t of r.routeTables || []) add('route-table', t.RouteTableId, nameTag(t.Tags), t.VpcId, {
    main: (t.Associations || []).some((a) => a.Main), subnets: (t.Associations || []).map((a) => a.SubnetId).filter(Boolean), gateways: (t.Associations || []).map((a) => a.GatewayId).filter(Boolean),
    routes: (t.Routes || []).map((x) => {
      const target = x.GatewayId ? { type: /^igw-/.test(x.GatewayId) ? 'igw' : /^vgw-/.test(x.GatewayId) ? 'vgw' : x.GatewayId === 'local' ? 'local' : /^vpce-/.test(x.GatewayId) ? 'endpoint' : 'gateway', id: x.GatewayId }
        : x.NatGatewayId ? { type: 'nat', id: x.NatGatewayId } : x.TransitGatewayId ? { type: 'tgw', id: x.TransitGatewayId } : x.VpcPeeringConnectionId ? { type: 'peering', id: x.VpcPeeringConnectionId }
        : x.EgressOnlyInternetGatewayId ? { type: 'eigw', id: x.EgressOnlyInternetGatewayId } : x.NetworkInterfaceId ? { type: 'eni', id: x.NetworkInterfaceId }
        : x.InstanceId ? { type: 'instance', id: x.InstanceId } : x.VpcEndpointId ? { type: 'endpoint', id: x.VpcEndpointId } : x.CoreNetworkArn ? { type: 'cloudwan', id: x.CoreNetworkArn } : { type: 'other', id: null };
      return { dest: x.DestinationCidrBlock || x.DestinationIpv6CidrBlock || x.DestinationPrefixListId || null, target, state: x.State || 'active' };
    }) });
  for (const g of r.igws || []) add('igw', g.InternetGatewayId, nameTag(g.Tags), g.Attachments?.[0]?.VpcId, { vpcs: (g.Attachments || []).map((a) => a.VpcId) });
  for (const g of r.eigws || []) add('eigw', g.EgressOnlyInternetGatewayId, nameTag(g.Tags), g.Attachments?.[0]?.VpcId, { vpcs: (g.Attachments || []).map((a) => a.VpcId) });
  for (const n of (r.nats || []).filter((x) => !['deleted', 'failed'].includes(x.State))) add('nat', n.NatGatewayId, nameTag(n.Tags), n.VpcId, { subnet: n.SubnetId,
    public: n.ConnectivityType !== 'private', publicIps: (n.NatGatewayAddresses || []).map((a) => a.PublicIp).filter(Boolean), state: n.State });
  for (const g of r.sgs || []) add('sg', g.GroupId, g.GroupName, g.VpcId, { groupName: g.GroupName, description: g.Description || null, isDefault: g.GroupName === 'default',
    ingress: (g.IpPermissions || []).map(sgRule), egress: (g.IpPermissionsEgress || []).map(sgRule), owner: g.OwnerId || null });
  for (const a of r.nacls || []) add('nacl', a.NetworkAclId, nameTag(a.Tags), a.VpcId, { isDefault: !!a.IsDefault, subnets: (a.Associations || []).map((x) => x.SubnetId),
    entries: (a.Entries || []).map((e) => ({ n: e.RuleNumber, egress: !!e.Egress, proto: proto(e.Protocol), from: e.PortRange?.From ?? null, to: e.PortRange?.To ?? null,
      cidr: e.CidrBlock || e.Ipv6CidrBlock, action: e.RuleAction })) });
  const side = (s) => s && { account: s.OwnerId, vpc: s.VpcId, region: s.Region || region, cidrs: (s.CidrBlockSet || [{ CidrBlock: s.CidrBlock }]).map((c) => c.CidrBlock).filter(Boolean) };
  for (const p of (r.peerings || []).filter((x) => !['deleted', 'rejected', 'failed', 'expired'].includes(x.Status?.Code))) add('peering', p.VpcPeeringConnectionId, nameTag(p.Tags), null,
    { requester: side(p.RequesterVpcInfo), accepter: side(p.AccepterVpcInfo), status: p.Status?.Code || null });
  for (const t of r.tgws || []) add('tgw', t.TransitGatewayId, nameTag(t.Tags), null, { owner: t.OwnerId, asn: t.Options?.AmazonSideAsn || null, state: t.State,
    autoAccept: t.Options?.AutoAcceptSharedAttachments === 'enable' });
  for (const a of (r.tgwAttachments || []).filter((x) => !['deleted', 'failed', 'rejected'].includes(x.State))) add('tgw-attachment', a.TransitGatewayAttachmentId, nameTag(a.Tags),
    a.ResourceType === 'vpc' ? a.ResourceId : null, { tgw: a.TransitGatewayId, tgwOwner: a.TransitGatewayOwnerId, resourceType: a.ResourceType, resourceId: a.ResourceId,
      resourceOwner: a.ResourceOwnerId, state: a.State });
  for (const v of (r.vpns || []).filter((x) => x.State !== 'deleted')) add('vpn', v.VpnConnectionId, nameTag(v.Tags), null, { vgw: v.VpnGatewayId || null, tgw: v.TransitGatewayId || null,
    cgw: v.CustomerGatewayId, state: v.State, staticRoutes: !!v.Options?.StaticRoutesOnly,
    tunnels: (v.VgwTelemetry || []).map((t) => ({ outsideIp: t.OutsideIpAddress, status: t.Status, detail: t.StatusMessage || null })) });
  for (const c of (r.cgws || []).filter((x) => x.State !== 'deleted')) add('cgw', c.CustomerGatewayId, nameTag(c.Tags), null, { ip: c.IpAddress, asn: c.BgpAsn || null, device: c.DeviceName || null });
  for (const g of (r.vgws || []).filter((x) => x.State !== 'deleted')) add('vgw', g.VpnGatewayId, nameTag(g.Tags), g.VpcAttachments?.find((a) => a.State === 'attached')?.VpcId,
    { vpcs: (g.VpcAttachments || []).filter((a) => a.State === 'attached').map((a) => a.VpcId), asn: g.AmazonSideAsn || null });
  for (const e of (r.endpoints || []).filter((x) => !['deleted', 'failed', 'rejected'].includes(String(x.State).toLowerCase()))) {
    let policy = null; try { policy = e.PolicyDocument ? JSON.parse(e.PolicyDocument) : null; } catch { policy = null; }
    const open = !policy || (policy.Statement || []).some((s) => s.Effect === 'Allow' && (s.Principal === '*' || s.Principal?.AWS === '*') && [].concat(s.Action).includes('*') && [].concat(s.Resource).includes('*') && !s.Condition);
    add('endpoint', e.VpcEndpointId, nameTag(e.Tags), e.VpcId, { service: e.ServiceName, kind: e.VpcEndpointType, subnets: e.SubnetIds || [], groups: (e.Groups || []).map((g) => g.GroupId),
      routeTables: e.RouteTableIds || [], policyOpen: open });
  }
  for (const n of r.enis || []) add('eni', n.NetworkInterfaceId, n.Description || n.NetworkInterfaceId, n.VpcId, { subnet: n.SubnetId, privateIp: n.PrivateIpAddress || null,
    publicIp: n.Association?.PublicIp || null, publicIps: [...new Set((n.PrivateIpAddresses || []).map((p) => p.Association?.PublicIp).filter(Boolean))], ipv6: (n.Ipv6Addresses || []).map((x) => x.Ipv6Address),
    groups: (n.Groups || []).map((g) => g.GroupId), kind: n.InterfaceType || 'interface', instance: n.Attachment?.InstanceId || null, requester: n.RequesterId || null,
    managed: !!n.RequesterManaged, description: n.Description || null, status: n.Status, owner: n.OwnerId || null });
  for (const f of r.flowLogs || []) add('flow-log', f.FlowLogId, null, /^vpc-/.test(f.ResourceId) ? f.ResourceId : null, { resource: f.ResourceId, status: f.FlowLogStatus, traffic: f.TrafficType,
    destination: f.LogDestinationType || null, arn: f.LogDestination || null, format: f.LogFormat || null, fileFormat: f.DestinationOptions?.FileFormat || 'plain-text',
    hive: !!f.DestinationOptions?.HiveCompatiblePartitions, perHour: !!f.DestinationOptions?.PerHourPartition });
  // Direct Connect
  for (const c of r.dxConnections || []) add('dx-connection', c.connectionId, c.connectionName, null, { location: c.location, bandwidth: c.bandwidth, state: c.connectionState, partner: c.partnerName || c.providerName || null,
    owner: c.ownerAccount || null, lag: c.lagId || null, macsec: !!c.macSecCapable });
  for (const v of r.dxVifs || []) add('dx-vif', v.virtualInterfaceId, v.virtualInterfaceName, null, { kind: v.virtualInterfaceType, connection: v.connectionId, vgw: v.virtualGatewayId || null,
    dxgw: v.directConnectGatewayId || null, vlan: v.vlan, asn: v.asn, amazonAsn: v.amazonSideAsn || null, state: v.virtualInterfaceState, owner: v.ownerAccount || null,
    bgp: (v.bgpPeers || []).map((b) => ({ status: b.bgpStatus, state: b.bgpPeerState, family: b.addressFamily, customer: b.customerAddress || null })),
    prefixes: (v.routeFilterPrefixes || []).map((p) => p.cidr) });
  for (const g of r.dxGateways || []) add('dx-gateway', g.directConnectGatewayId, g.directConnectGatewayName, null, { asn: g.amazonSideAsn, state: g.directConnectGatewayState, owner: g.ownerAccount || null });
  for (const a of r.dxAssociations || []) add('dx-association', a.associationId, null, null, { dxgw: a.directConnectGatewayId, dxgwOwner: a.directConnectGatewayOwnerAccount || null,
    gateway: a.associatedGateway?.id || a.virtualGatewayId || null, gatewayType: a.associatedGateway?.type || (a.virtualGatewayId ? 'virtualPrivateGateway' : null), gatewayOwner: a.associatedGateway?.ownerAccount || a.virtualGatewayOwnerAccount || null,
    gatewayRegion: a.associatedGateway?.region || a.virtualGatewayRegion || null, prefixes: (a.allowedPrefixesToDirectConnectGateway || []).map((p) => p.cidr), state: a.associationState });
  // transit gateway route tables: which attachments are associated, and the routes (static and propagated) they see
  for (const t of r.tgwRouteTables || []) add('tgw-route-table', t.TransitGatewayRouteTableId, nameTag(t.Tags), null, { tgw: t.TransitGatewayId, default: !!t.DefaultAssociationRouteTable,
    associations: (t.associations || []).map((a) => ({ attachment: a.TransitGatewayAttachmentId, resourceType: a.ResourceType, resourceId: a.ResourceId })),
    routes: (t.routes || []).map((x) => ({ dest: x.DestinationCidrBlock || x.PrefixListId, type: x.Type, state: x.State,
      attachments: (x.TransitGatewayAttachments || []).map((a) => ({ attachment: a.TransitGatewayAttachmentId, resourceType: a.ResourceType, resourceId: a.ResourceId })) })) });
  // Client VPN: people connecting into a VPC
  for (const c of r.clientVpns || []) add('client-vpn', c.ClientVpnEndpointId, nameTag(c.Tags) || c.Description, c.VpcId, { cidr: c.ClientCidrBlock, split: !!c.SplitTunnel, status: c.Status?.Code || null,
    auth: (c.AuthenticationOptions || []).map((a) => a.Type), targets: (c.targets || []).map((t) => ({ subnet: t.TargetNetworkId, status: t.Status?.Code })), groups: c.SecurityGroupIds || [],
    rules: (c.rules || []).map((x) => ({ cidr: x.DestinationCidr, group: x.GroupId || null, everyone: !!x.AccessAll, status: x.Status?.Code })), dns: c.DnsName || null, connectionLog: !!c.ConnectionLogOptions?.Enabled });
  // PrivateLink: services this account offers, and who connects to them
  for (const v of r.endpointServices || []) add('endpoint-service', v.ServiceId, v.ServiceName, null, { name: v.ServiceName, acceptance: !!v.AcceptanceRequired, nlbs: v.NetworkLoadBalancerArns || [], glbs: v.GatewayLoadBalancerArns || [],
    state: v.ServiceState, connections: (v.connections || []).map((c) => ({ account: c.VpcEndpointOwner, endpoint: c.VpcEndpointId, state: c.VpcEndpointState })) });
  for (const p of r.prefixLists || []) add('prefix-list', p.PrefixListId, p.PrefixListName, null, { owner: p.OwnerId, managedByAws: p.OwnerId === 'AWS', entries: (p.entries || []).map((e) => e.Cidr), max: p.MaxEntries || null });
  // Route 53 Resolver: DNS in and out of VPCs (forwarding rules show where names are resolved, often on-premises)
  for (const e of r.resolverEndpoints || []) add('resolver-endpoint', e.Id, e.Name, e.HostVPCId, { direction: e.Direction, ips: (e.ips || []).map((x) => ({ ip: x.Ip, subnet: x.SubnetId })), groups: e.SecurityGroupIds || [], status: e.Status });
  for (const x of r.resolverRules || []) add('resolver-rule', x.Id, x.Name, null, { domain: x.DomainName, type: x.RuleType, endpoint: x.ResolverEndpointId || null, targets: (x.TargetIps || []).map((t) => `${t.Ip || t.Ipv6}:${t.Port}`),
    vpcs: (x.vpcs || []), owner: x.OwnerId || null, shared: x.ShareStatus || null });
  for (const f of r.firewalls || []) add('firewall', f.FirewallArn, f.FirewallName, f.VpcId, { subnets: (f.SubnetMappings || []).map((m) => m.SubnetId), policy: f.FirewallPolicyArn?.split('/').pop() || null,
    endpoints: f.endpoints || [] });
  for (const b of r.lbs || []) add('lb', b.LoadBalancerArn, b.LoadBalancerName, b.VpcId, { scheme: b.Scheme, kind: b.Type, dns: b.DNSName, subnets: (b.AvailabilityZones || []).map((z) => z.SubnetId).filter(Boolean),
    groups: b.SecurityGroups || [], listeners: (b.listeners || []).map((l) => ({ port: l.Port, proto: l.Protocol })) });
  // subnets shared through AWS RAM: which share, which subnets, with whom (accounts, OUs, the organization)
  for (const x of r.ramShares || []) {
    const subnets = (x.resources || []).map((a) => String(a.arn || '').split('/').pop()).filter((id) => /^subnet-/.test(id));
    if (!subnets.length) continue;
    add('ram-share', x.resourceShareArn, x.name, null, { subnets, allowExternal: !!x.allowExternalPrincipals, status: x.status || null,
      principals: (x.principals || []).map((p) => ({ id: p.id, external: !!p.external })) });
  }
  return out;
}

/** The reader, given credentials: read(regions) → { items, skipped }. */
export function awsNetworkReader(credentials) {
  return {
    async read(regions) {
      const items = [], skipped = new Set();
      for (const region of regions) {
        const ec2 = new EC2Client({ region, credentials }), nfw = new NetworkFirewallClient({ region, credentials }), elb = new ElasticLoadBalancingV2Client({ region, credentials });
        const all = async (label, Cmd, key, input = {}, client = ec2, tokenIn = 'NextToken', tokenOut = 'NextToken') => {
          const out = []; let token;
          try {
            do { bump('apiCalls'); const r = await client.send(new Cmd({ ...input, ...(token ? { [tokenIn]: token } : {}) })); out.push(...(r[key] || [])); token = r[tokenOut]; } while (token);
          } catch (e) { if (DENIED.test(`${e.name} ${e.message}`)) { skipped.add(label); return []; } throw e; }
          return out;
        };
        const [vpcs, subnets, routeTables, igws, eigws, nats, sgs, nacls, peerings, tgws, tgwAttachments, vpns, cgws, vgws, endpoints, enis, flowLogs] = await Promise.all([
          all('ec2:DescribeVpcs', DescribeVpcsCommand, 'Vpcs'), all('ec2:DescribeSubnets', DescribeSubnetsCommand, 'Subnets'),
          all('ec2:DescribeRouteTables', DescribeRouteTablesCommand, 'RouteTables'), all('ec2:DescribeInternetGateways', DescribeInternetGatewaysCommand, 'InternetGateways'),
          all('ec2:DescribeEgressOnlyInternetGateways', DescribeEgressOnlyInternetGatewaysCommand, 'EgressOnlyInternetGateways'), all('ec2:DescribeNatGateways', DescribeNatGatewaysCommand, 'NatGateways'),
          all('ec2:DescribeSecurityGroups', DescribeSecurityGroupsCommand, 'SecurityGroups'), all('ec2:DescribeNetworkAcls', DescribeNetworkAclsCommand, 'NetworkAcls'),
          all('ec2:DescribeVpcPeeringConnections', DescribeVpcPeeringConnectionsCommand, 'VpcPeeringConnections'), all('ec2:DescribeTransitGateways', DescribeTransitGatewaysCommand, 'TransitGateways'),
          all('ec2:DescribeTransitGatewayAttachments', DescribeTransitGatewayAttachmentsCommand, 'TransitGatewayAttachments'),
          // these three have no paging
          all('ec2:DescribeVpnConnections', DescribeVpnConnectionsCommand, 'VpnConnections'), all('ec2:DescribeCustomerGateways', DescribeCustomerGatewaysCommand, 'CustomerGateways'),
          all('ec2:DescribeVpnGateways', DescribeVpnGatewaysCommand, 'VpnGateways'), all('ec2:DescribeVpcEndpoints', DescribeVpcEndpointsCommand, 'VpcEndpoints'),
          all('ec2:DescribeNetworkInterfaces', DescribeNetworkInterfacesCommand, 'NetworkInterfaces'), all('ec2:DescribeFlowLogs', DescribeFlowLogsCommand, 'FlowLogs'),
        ]);
        // Network Firewall: list, then describe each for its VPC and subnets
        const fwList = await all('network-firewall:ListFirewalls', ListFirewallsCommand, 'Firewalls', {}, nfw);
        const firewalls = [];
        for (const f of fwList) {
          try { bump('apiCalls'); const d = await nfw.send(new DescribeFirewallCommand({ FirewallArn: f.FirewallArn })); firewalls.push({ ...d.Firewall, endpoints: Object.values(d.FirewallStatus?.SyncStates || {}).map((s) => s.Attachment?.EndpointId).filter(Boolean) }); }
          catch (e) { if (DENIED.test(`${e.name} ${e.message}`)) { skipped.add('network-firewall:DescribeFirewall'); break; } throw e; }
        }
        // load balancers and their listeners (the ports they take from the internet)
        const lbs = await all('elasticloadbalancing:DescribeLoadBalancers', DescribeLoadBalancersCommand, 'LoadBalancers', {}, elb, 'Marker', 'NextMarker');
        for (const b of lbs) {
          try { bump('apiCalls'); b.listeners = (await elb.send(new DescribeListenersCommand({ LoadBalancerArn: b.LoadBalancerArn }))).Listeners || []; }
          catch (e) { if (DENIED.test(`${e.name} ${e.message}`)) { skipped.add('elasticloadbalancing:DescribeListeners'); b.listeners = []; } else throw e; }
        }
        // Direct Connect: connections and virtual interfaces per region; gateways are global (read once)
        const dx = new DirectConnectClient({ region, credentials });
        const once = async (label, Cmd, key, input = {}, client = dx) => { try { bump('apiCalls'); return (await client.send(new Cmd(input)))[key] || []; } catch (e) { if (DENIED.test(`${e.name} ${e.message}`)) { skipped.add(label); return []; } throw e; } };
        const [dxConnections, dxVifs] = await Promise.all([once('directconnect:DescribeConnections', DescribeConnectionsCommand, 'connections'), once('directconnect:DescribeVirtualInterfaces', DescribeVirtualInterfacesCommand, 'virtualInterfaces')]);
        let dxGateways = [], dxAssociations = [];
        if (region === regions[0]) {
          dxGateways = await all('directconnect:DescribeDirectConnectGateways', DescribeDirectConnectGatewaysCommand, 'directConnectGateways', {}, dx, 'nextToken', 'nextToken');
          const seen = new Set();
          const ask = async (input) => { for (const a of await all('directconnect:DescribeDirectConnectGatewayAssociations', DescribeDirectConnectGatewayAssociationsCommand, 'directConnectGatewayAssociations', input, dx, 'nextToken', 'nextToken')) if (!seen.has(a.associationId)) { seen.add(a.associationId); dxAssociations.push(a); } };
          for (const g of dxGateways) await ask({ directConnectGatewayId: g.directConnectGatewayId });
        }
        // a Direct Connect gateway in another account can still be associated with this account's gateways
        {
          const seen = new Set(dxAssociations.map((a) => a.associationId));
          for (const id of [...vgws.map((g) => g.VpnGatewayId), ...tgws.map((t) => t.TransitGatewayId)]) {
            for (const a of await all('directconnect:DescribeDirectConnectGatewayAssociations', DescribeDirectConnectGatewayAssociationsCommand, 'directConnectGatewayAssociations', { associatedGatewayId: id }, dx, 'nextToken', 'nextToken')) if (!seen.has(a.associationId)) { seen.add(a.associationId); dxAssociations.push(a); }
          }
        }
        // transit gateway route tables (for the gateways this account owns)
        const tgwRouteTables = await all('ec2:DescribeTransitGatewayRouteTables', DescribeTransitGatewayRouteTablesCommand, 'TransitGatewayRouteTables');
        for (const t of tgwRouteTables) {
          t.associations = await all('ec2:GetTransitGatewayRouteTableAssociations', GetTransitGatewayRouteTableAssociationsCommand, 'Associations', { TransitGatewayRouteTableId: t.TransitGatewayRouteTableId });
          try { bump('apiCalls'); t.routes = (await ec2.send(new SearchTransitGatewayRoutesCommand({ TransitGatewayRouteTableId: t.TransitGatewayRouteTableId, Filters: [{ Name: 'type', Values: ['static', 'propagated'] }], MaxResults: 1000 }))).Routes || []; }
          catch (e) { if (DENIED.test(`${e.name} ${e.message}`)) { skipped.add('ec2:SearchTransitGatewayRoutes'); t.routes = []; } else throw e; }
        }
        // Client VPN endpoints, their subnets and who may reach what
        const clientVpns = await all('ec2:DescribeClientVpnEndpoints', DescribeClientVpnEndpointsCommand, 'ClientVpnEndpoints');
        for (const c of clientVpns) {
          c.targets = await all('ec2:DescribeClientVpnTargetNetworks', DescribeClientVpnTargetNetworksCommand, 'ClientVpnTargetNetworks', { ClientVpnEndpointId: c.ClientVpnEndpointId });
          c.rules = await all('ec2:DescribeClientVpnAuthorizationRules', DescribeClientVpnAuthorizationRulesCommand, 'AuthorizationRules', { ClientVpnEndpointId: c.ClientVpnEndpointId });
        }
        // PrivateLink services offered, and the endpoints connected to them
        const endpointServices = await all('ec2:DescribeVpcEndpointServiceConfigurations', DescribeVpcEndpointServiceConfigurationsCommand, 'ServiceConfigurations');
        if (endpointServices.length) {
          const conns = await all('ec2:DescribeVpcEndpointConnections', DescribeVpcEndpointConnectionsCommand, 'VpcEndpointConnections');
          for (const v of endpointServices) v.connections = conns.filter((c) => c.ServiceId === v.ServiceId);
        }
        // prefix lists: your own, and AWS's for S3 and DynamoDB (gateway endpoints route to them)
        const prefixLists = (await all('ec2:DescribeManagedPrefixLists', DescribeManagedPrefixListsCommand, 'PrefixLists')).filter((p) => p.OwnerId !== 'AWS' || /\.(s3|dynamodb)$/.test(p.PrefixListName || ''));
        for (const p of prefixLists) p.entries = await all('ec2:GetManagedPrefixListEntries', GetManagedPrefixListEntriesCommand, 'Entries', { PrefixListId: p.PrefixListId });
        // Route 53 Resolver
        const r53 = new Route53ResolverClient({ region, credentials });
        const resolverEndpoints = await all('route53resolver:ListResolverEndpoints', ListResolverEndpointsCommand, 'ResolverEndpoints', {}, r53);
        for (const e of resolverEndpoints) e.ips = await all('route53resolver:ListResolverEndpointIpAddresses', ListResolverEndpointIpAddressesCommand, 'IpAddresses', { ResolverEndpointId: e.Id }, r53);
        const resolverRules = (await all('route53resolver:ListResolverRules', ListResolverRulesCommand, 'ResolverRules', {}, r53)).filter((x) => x.RuleType !== 'RECURSIVE');
        if (resolverRules.length) {
          const assoc = await all('route53resolver:ListResolverRuleAssociations', ListResolverRuleAssociationsCommand, 'ResolverRuleAssociations', {}, r53);
          for (const x of resolverRules) x.vpcs = assoc.filter((a) => a.ResolverRuleId === x.Id).map((a) => a.VPCId);
        }
        // subnets this account shares (AWS RAM): the shares, then their subnets and principals, matched by share
        const ram = new RAMClient({ region, credentials });
        const ramShares = (await all('ram:GetResourceShares', GetResourceSharesCommand, 'resourceShares', { resourceOwner: 'SELF', resourceShareStatus: 'ACTIVE' }, ram, 'nextToken', 'nextToken'));
        if (ramShares.length) {
          const [res, princ] = await Promise.all([all('ram:ListResources', ListResourcesCommand, 'resources', { resourceOwner: 'SELF', resourceType: 'ec2:Subnet' }, ram, 'nextToken', 'nextToken'),
            all('ram:ListPrincipals', ListPrincipalsCommand, 'principals', { resourceOwner: 'SELF' }, ram, 'nextToken', 'nextToken')]);
          for (const x of ramShares) { x.resources = res.filter((r) => r.resourceShareArn === x.resourceShareArn); x.principals = princ.filter((p) => p.resourceShareArn === x.resourceShareArn); }
        }
        items.push(...normalizeAwsRegion(region, { ramShares, vpcs, subnets, routeTables, igws, eigws, nats, sgs, nacls, peerings, tgws, tgwAttachments, vpns, cgws, vgws, endpoints, enis, flowLogs, firewalls, lbs,
          dxConnections, dxVifs, dxGateways, dxAssociations, tgwRouteTables, clientVpns, endpointServices, prefixLists, resolverEndpoints, resolverRules }));
      }
      return { items, skipped: [...skipped] };
    },
  };
}

export const AWS_NETWORK_READS = [
  'ec2:DescribeVpcs', 'ec2:DescribeSubnets', 'ec2:DescribeRouteTables', 'ec2:DescribeInternetGateways', 'ec2:DescribeEgressOnlyInternetGateways', 'ec2:DescribeNatGateways',
  'ec2:DescribeSecurityGroups', 'ec2:DescribeNetworkAcls', 'ec2:DescribeVpcPeeringConnections', 'ec2:DescribeTransitGateways', 'ec2:DescribeTransitGatewayAttachments',
  'ec2:DescribeVpnConnections', 'ec2:DescribeCustomerGateways', 'ec2:DescribeVpnGateways', 'ec2:DescribeVpcEndpoints', 'ec2:DescribeNetworkInterfaces', 'ec2:DescribeFlowLogs',
  'network-firewall:ListFirewalls', 'network-firewall:DescribeFirewall', 'elasticloadbalancing:DescribeLoadBalancers', 'elasticloadbalancing:DescribeListeners',
  'ec2:DescribeTransitGatewayRouteTables', 'ec2:SearchTransitGatewayRoutes', 'ec2:GetTransitGatewayRouteTableAssociations', 'ec2:DescribeClientVpnEndpoints', 'ec2:DescribeClientVpnTargetNetworks',
  'ec2:DescribeClientVpnAuthorizationRules', 'ec2:DescribeVpcEndpointServiceConfigurations', 'ec2:DescribeVpcEndpointConnections', 'ec2:DescribeManagedPrefixLists', 'ec2:GetManagedPrefixListEntries',
  'directconnect:DescribeConnections', 'directconnect:DescribeVirtualInterfaces', 'directconnect:DescribeDirectConnectGateways', 'directconnect:DescribeDirectConnectGatewayAssociations',
  'route53resolver:ListResolverEndpoints', 'route53resolver:ListResolverEndpointIpAddresses', 'route53resolver:ListResolverRules', 'route53resolver:ListResolverRuleAssociations',
  'ram:GetResourceShares', 'ram:ListResources', 'ram:ListPrincipals',
];
