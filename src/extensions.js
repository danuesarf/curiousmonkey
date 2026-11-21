// Extensions: optional features a workspace turns on or off (Admin → Extensions). Each one says what it adds and what
// the scanner needs to read for it. Turning one off hides it and stops its reads; what it stored stays until it is
// turned on again (or the account or connection is removed).
import { query } from './db.js';

export const EXTENSIONS = [
  {
    key: 'networking',
    name: 'Networking',
    summary: 'Network analyzer: VPCs, subnets, route tables, gateways, security groups, network ACLs, firewalls, peering, transit gateways, VPNs, Direct Connect and PrivateLink in AWS and Google Cloud, with VPC flow logs to tell used lines from unused ones.',
    adds: [
      'A Networking page: a Space-like scene and a map of how your VPCs and networks connect (peering, transit gateways, VPNs, Direct Connect, PrivateLink, between AWS and Google Cloud too) and what reaches them from the internet.',
      'VPC flow logs read from S3: which connections are used and which are not, replayed hour by hour, and what the internet actually reached.',
      'Exposure: what the internet can reach, port by port, through security groups, firewall rules and load balancers.',
      'Network findings: admin and database ports open to the internet, default networks, missing flow logs, peering with outsiders, VPN tunnels down.',
    ],
    reads: {
      aws: 'ec2:Describe* for VPC networking, directconnect:Describe*, route53resolver:List*, network-firewall:List*/Describe*, elasticloadbalancing:DescribeLoadBalancers and DescribeListeners; and VPC flow log files in S3 (only keys under AWSLogs/…/vpcflowlogs/). Read-only; added to the scanner policy shown on Accounts.',
      gcp: 'compute.*.list for networks, subnetworks, firewalls, firewall policies, routers, routes, VPN gateways and tunnels, interconnect attachments, service attachments, addresses, forwarding rules and instances; networkconnectivity hubs and spokes. Read-only.',
    },
  },
];
const KNOWN = new Set(EXTENSIONS.map((e) => e.key));

let cache = null, cachedAt = 0;
/** Keys of the extensions turned on. Cached for 10 s: the worker asks once per account scan. */
export async function enabledExtensions({ fresh = false } = {}) {
  if (!fresh && cache && Date.now() - cachedAt < 10e3) return cache;
  const rows = (await query('SELECT key FROM extensions WHERE enabled').catch((e) => { if (e.code === '42P01') return { rows: [] }; throw e; })).rows;
  cache = new Set(rows.map((r) => r.key).filter((k) => KNOWN.has(k))); cachedAt = Date.now();
  return cache;
}
export const isEnabled = async (key) => (await enabledExtensions()).has(key);

/** Every extension with its state, for the Admin page. */
export async function listExtensions() {
  const rows = new Map((await query(`SELECT e.*, u.name AS updated_by_name FROM extensions e LEFT JOIN users u ON u.id = e.updated_by`)).rows.map((r) => [r.key, r]));
  return EXTENSIONS.map((e) => { const r = rows.get(e.key); return { ...e, enabled: !!r?.enabled, updatedAt: r?.updated_at || null, updatedBy: r?.updated_by_name || null }; });
}

/** Turn one on or off. Returns whether it changed. */
export async function setExtension(key, enabled, userId) {
  if (!KNOWN.has(key)) throw Object.assign(new Error('No such extension.'), { status: 404 });
  const r = await query(`INSERT INTO extensions(key, enabled, updated_by, updated_at) VALUES ($1, $2, $3, now())
    ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = now() WHERE extensions.enabled IS DISTINCT FROM EXCLUDED.enabled
    RETURNING key`, [key, !!enabled, userId || null]);
  cache = null;
  return r.rowCount > 0;
}
