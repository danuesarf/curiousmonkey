// Google Cloud networking, normalised the same way as AWS's (src/network/awsReader.js): one project's VPC networks,
// subnetworks, firewall rules and network firewall policies, Cloud Routers with their Cloud NAT and BGP peers,
// routes, HA and Classic VPN gateways, peer (external) VPN gateways, VPN tunnels, Interconnect attachments, external
// addresses, forwarding rules (load balancers) and instances (where they sit, their tags, external IPs and service
// accounts, which is how firewall rules pick their targets). Only metadata: never disks or data.
const last = (url) => String(url || '').split('/').pop();
/** projects/<p>/global/networks/<n> from any network URL (selfLink or partial). */
export const netPath = (url) => { const m = String(url || '').match(/projects\/([^/]+)\/global\/networks\/([^/]+)/); return m ? `projects/${m[1]}/global/networks/${m[2]}` : null; };
const region = (url) => String(url || '').match(/(?:regions|zones)\/([^/]+)/)?.[1] || null;

export const GCP_NETWORK_KINDS = ['networks', 'subnetworks', 'firewalls', 'firewallPolicies', 'routers', 'routes', 'vpnGateways', 'targetVpnGateways', 'externalVpnGateways',
  'vpnTunnels', 'interconnectAttachments', 'addresses', 'forwardingRules', 'instances', 'serviceAttachments', 'nccHubs', 'nccSpokes', 'xpnResources'];

/** One project's raw lists → [{ type, id, name, vpc, region, data }]. `vpc` is the network path. */
export function normalizeGcpProject(projectId, r) {
  const out = [];
  const add = (type, id, name, vpc, reg, data) => out.push({ type, id: String(id), name: name || String(id), vpc: vpc || null, region: reg || null, data });
  for (const n of r.networks || []) {
    const path = `projects/${projectId}/global/networks/${n.name}`;
    add('network', path, n.name, path, null, { autoSubnets: !!n.autoCreateSubnetworks, legacy: !n.subnetworks && !!n.IPv4Range, routingMode: n.routingConfig?.routingMode || null, mtu: n.mtu || null,
      peerings: (n.peerings || []).map((p) => ({ name: p.name, network: netPath(p.network), state: p.state, exportCustom: !!p.exportCustomRoutes, importCustom: !!p.importCustomRoutes })),
      firewallPolicy: n.firewallPolicy ? last(n.firewallPolicy) : null, policyOrder: n.networkFirewallPolicyEnforcementOrder || null });
  }
  for (const s of r.subnetworks || []) add('subnet', `projects/${projectId}/regions/${region(s.region)}/subnetworks/${s.name}`, s.name, netPath(s.network), region(s.region), {
    cidr: s.ipCidrRange, secondary: (s.secondaryIpRanges || []).map((x) => ({ name: x.rangeName, cidr: x.ipCidrRange })), privateGoogleAccess: !!s.privateIpGoogleAccess,
    flowLogs: !!s.logConfig?.enable || !!s.enableFlowLogs, purpose: s.purpose || 'PRIVATE', stack: s.stackType || null });
  for (const f of r.firewalls || []) add('firewall', `projects/${projectId}/global/firewalls/${f.name}`, f.name, netPath(f.network), null, {
    direction: f.direction || 'INGRESS', priority: f.priority ?? 1000, action: f.allowed ? 'allow' : 'deny',
    rules: (f.allowed || f.denied || []).map((x) => ({ proto: x.IPProtocol, ports: x.ports || [] })),
    sourceRanges: f.sourceRanges || [], destinationRanges: f.destinationRanges || [], sourceTags: f.sourceTags || [], sourceServiceAccounts: f.sourceServiceAccounts || [],
    targetTags: f.targetTags || [], targetServiceAccounts: f.targetServiceAccounts || [], disabled: !!f.disabled, logging: !!f.logConfig?.enable });
  for (const p of r.firewallPolicies || []) add('firewall-policy', `projects/${projectId}/global/firewallPolicies/${p.name}`, p.name, null, null, {
    networks: (p.associations || []).map((a) => netPath(a.attachmentTarget)).filter(Boolean),
    rules: (p.rules || []).map((x) => ({ direction: x.direction, priority: x.priority, action: x.action, disabled: !!x.disabled, sourceRanges: x.match?.srcIpRanges || [],
      destinationRanges: x.match?.destIpRanges || [], layer4: (x.match?.layer4Configs || []).map((l) => ({ proto: l.ipProtocol, ports: l.ports || [] })),
      targetServiceAccounts: x.targetServiceAccounts || [], targetTags: (x.targetSecureTags || []).map((t) => t.name), logging: !!x.enableLogging })) });
  for (const x of r.routers || []) add('router', `projects/${projectId}/regions/${region(x.region)}/routers/${x.name}`, x.name, netPath(x.network), region(x.region), {
    asn: x.bgp?.asn || null, peers: (x.bgpPeers || []).map((p) => ({ name: p.name, ip: p.peerIpAddress || null, asn: p.peerAsn || null, tunnel: p.interfaceName || null })),
    nats: (x.nats || []).map((n) => ({ name: n.name, ranges: n.sourceSubnetworkIpRangesToNat || null, subnets: (n.subnetworks || []).map((s) => last(s.name)), ips: (n.natIps || []).map(last),
      allocation: n.natIpAllocateOption || null, logging: !!n.logConfig?.enable })),
    interconnect: (x.interfaces || []).some((i) => i.linkedInterconnectAttachment) });
  for (const x of (r.routes || []).filter((y) => !y.name?.startsWith('default-route-') || y.destRange === '0.0.0.0/0')) add('route', `projects/${projectId}/global/routes/${x.name}`, x.name, netPath(x.network), null, {
    dest: x.destRange, priority: x.priority, tags: x.tags || [],
    nextHop: x.nextHopGateway ? { type: 'internet', id: last(x.nextHopGateway) } : x.nextHopVpnTunnel ? { type: 'vpn-tunnel', id: last(x.nextHopVpnTunnel) } : x.nextHopInstance ? { type: 'instance', id: last(x.nextHopInstance) }
      : x.nextHopIlb ? { type: 'ilb', id: last(x.nextHopIlb) } : x.nextHopPeering ? { type: 'peering', id: x.nextHopPeering } : x.nextHopIp ? { type: 'ip', id: x.nextHopIp } : { type: 'other', id: null } });
  for (const g of r.vpnGateways || []) add('vpn-gateway', `projects/${projectId}/regions/${region(g.region)}/vpnGateways/${g.name}`, g.name, netPath(g.network), region(g.region), {
    ips: (g.vpnInterfaces || []).map((i) => i.ipAddress).filter(Boolean), ha: true });
  for (const g of r.targetVpnGateways || []) add('vpn-gateway', `projects/${projectId}/regions/${region(g.region)}/targetVpnGateways/${g.name}`, g.name, netPath(g.network), region(g.region), {
    ips: g.ips || [], ha: false, tunnels: (g.tunnels || []).map(last) });
  for (const g of r.externalVpnGateways || []) add('peer-vpn-gateway', `projects/${projectId}/global/externalVpnGateways/${g.name}`, g.name, null, null, {
    ips: (g.interfaces || []).map((i) => i.ipAddress).filter(Boolean), redundancy: g.redundancyType || null, description: g.description || null });
  for (const t of r.vpnTunnels || []) {
    const gw = t.vpnGateway || t.targetVpnGateway;
    add('vpn-tunnel', `projects/${projectId}/regions/${region(t.region)}/vpnTunnels/${t.name}`, t.name, null, region(t.region), {
      peerIp: t.peerIp || null, status: t.status || null, detail: t.detailedStatus || null, gateway: gw ? `projects/${projectId}/regions/${region(t.region)}/${t.vpnGateway ? 'vpnGateways' : 'targetVpnGateways'}/${last(gw)}` : null,
      peerGateway: t.peerExternalGateway ? `projects/${projectId}/global/externalVpnGateways/${last(t.peerExternalGateway)}` : t.peerGcpGateway ? String(t.peerGcpGateway).replace(/^.*?(projects\/)/, '$1') : null,
      router: t.router ? last(t.router) : null, ikeVersion: t.ikeVersion || null });
  }
  for (const a of r.interconnectAttachments || []) add('interconnect', `projects/${projectId}/regions/${region(a.region)}/interconnectAttachments/${a.name}`, a.name, null, region(a.region), {
    type: a.type, state: a.state || a.operationalStatus || null, router: a.router ? last(a.router) : null, interconnect: a.interconnect ? last(a.interconnect) : null,
    partner: a.partnerMetadata?.partnerName || null, edge: a.edgeAvailabilityDomain || null });
  for (const a of (r.addresses || []).filter((x) => x.addressType === 'EXTERNAL')) add('address', `projects/${projectId}/${a.region ? `regions/${region(a.region)}` : 'global'}/addresses/${a.name}`, a.name, null, region(a.region), {
    ip: a.address, status: a.status, users: (a.users || []).map(last), tier: a.networkTier || null });
  // internal load balancers (they front Private Service Connect services) and Private Service Connect endpoints
  for (const f of r.forwardingRules || []) {
    const id = `projects/${projectId}/${f.region ? `regions/${region(f.region)}` : 'global'}/forwardingRules/${f.name}`;
    if (/serviceAttachments\/|all-apis|vpc-sc/.test(f.target || '')) add('psc-endpoint', id, f.name, netPath(f.network), region(f.region), { ip: f.IPAddress, target: /serviceAttachments\//.test(f.target) ? String(f.target).replace(/^.*?(projects\/)/, '$1') : f.target, status: f.pscConnectionStatus || null });
    else if (/^INTERNAL/.test(f.loadBalancingScheme || '')) add('ilb', id, f.name, netPath(f.network), region(f.region), { ip: f.IPAddress, ports: f.ports || (f.portRange ? [f.portRange] : f.allPorts ? ['all'] : []) });
  }
  for (const a of r.serviceAttachments || []) add('service-attachment', `projects/${projectId}/regions/${region(a.region)}/serviceAttachments/${a.name}`, a.name, null, region(a.region), {
    producer: String(a.targetService || a.producerForwardingRule || '').replace(/^.*?(projects\/)/, '$1'), preference: a.connectionPreference || null,
    accept: (a.consumerAcceptLists || []).map((x) => x.projectIdOrNum || x.networkUrl).filter(Boolean), reject: a.consumerRejectLists || [],
    connected: (a.connectedEndpoints || []).map((e) => ({ endpoint: String(e.endpoint || '').replace(/^.*?(projects\/)/, '$1'), status: e.status, network: netPath(e.consumerNetwork) })) });
  for (const h of r.nccHubs || []) add('ncc-hub', h.name, last(h.name), null, null, { state: h.state || null, routingVpcs: (h.routingVpcs || []).map((v) => netPath(v.uri)).filter(Boolean) });
  for (const x of r.nccSpokes || []) add('ncc-spoke', x.name, last(x.name), netPath(x.linkedVpcNetwork?.uri) || null, region(x.name), { hub: x.hub, state: x.state || null,
    kind: x.linkedVpcNetwork ? 'vpc' : x.linkedVpnTunnels ? 'vpn' : x.linkedInterconnectAttachments ? 'interconnect' : x.linkedRouterApplianceInstances ? 'router-appliance' : x.linkedProducerVpcNetwork ? 'producer-vpc' : 'other',
    uris: [...(x.linkedVpnTunnels?.uris || []), ...(x.linkedInterconnectAttachments?.uris || [])].map((u) => String(u).replace(/^.*?(projects\/)/, '$1')) });
  const services = (r.xpnResources || []).filter((x) => x.type === 'PROJECT').map((x) => x.id);
  if (services.length) add('shared-vpc', `projects/${projectId}/xpn`, `Shared VPC host ${projectId}`, null, null, { host: projectId, services });
  for (const f of (r.forwardingRules || []).filter((x) => /^EXTERNAL/.test(x.loadBalancingScheme || ''))) add('forwarding-rule', `projects/${projectId}/${f.region ? `regions/${region(f.region)}` : 'global'}/forwardingRules/${f.name}`, f.name, netPath(f.network), region(f.region), {
    ip: f.IPAddress, proto: f.IPProtocol, ports: f.ports || (f.portRange ? [f.portRange] : f.allPorts ? ['all'] : []), scheme: f.loadBalancingScheme, target: last(f.target || f.backendService) });
  for (const i of r.instances || []) add('instance', `projects/${projectId}/zones/${region(i.zone)}/instances/${i.name}`, i.name, netPath(i.networkInterfaces?.[0]?.network), region(i.zone), {
    status: i.status, tags: i.tags?.items || [], serviceAccounts: (i.serviceAccounts || []).map((s) => s.email),
    interfaces: (i.networkInterfaces || []).map((n) => ({ network: netPath(n.network), subnet: last(n.subnetwork), ip: n.networkIP, natIps: (n.accessConfigs || []).map((a) => a.natIP).filter(Boolean) })) });
  return out;
}

export const GCP_NETWORK_PERMISSIONS = ['compute.networks.list', 'compute.subnetworks.list', 'compute.firewalls.list', 'compute.networkFirewallPolicies.list', 'compute.routers.list', 'compute.routes.list',
  'compute.vpnGateways.list', 'compute.targetVpnGateways.list', 'compute.externalVpnGateways.list', 'compute.vpnTunnels.list', 'compute.interconnectAttachments.list',
  'compute.addresses.list', 'compute.forwardingRules.list', 'compute.globalForwardingRules.list', 'compute.instances.list', 'compute.serviceAttachments.list',
  'compute.projects.get', 'networkconnectivity.hubs.list', 'networkconnectivity.spokes.list'];
export const GCP_NETWORK_PREDEFINED = ['roles/compute.networkViewer', 'roles/networkconnectivity.hubViewer'];
