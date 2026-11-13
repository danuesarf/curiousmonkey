// What every Google Cloud principal can do and where it can come from, from IAM policies alone. No I/O: the
// scanner passes the snapshot in, the tests pass fixtures.
//
// Inheritance: a binding on the organization reaches every project, one on a folder every project under it, one on a
// project that project, one on a service account only that service account.
// Who can become a service account: holders of getAccessToken / signJwt / implicitDelegation (impersonate), of
// actAs (attach it to something they deploy), of serviceAccountKeys.create (mint a key), workload identity users
// (federated identities from AWS, GitHub... and GKE pods), and anyone holding one of its keys.

const IMPERSONATE = ['iam.serviceAccounts.getAccessToken', 'iam.serviceAccounts.implicitDelegation', 'iam.serviceAccounts.signJwt', 'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.getOpenIdToken'];
const ACT_AS = 'iam.serviceAccounts.actAs';
const MINT_KEY = 'iam.serviceAccountKeys.create';
const SET_IAM = /^resourcemanager\.(organizations|folders|projects)\.setIamPolicy$/;

/** What kind of identity an IAM member string names, and what is known about it from the string alone. */
export function parseMember(member) {
  const m = String(member);
  if (m === 'allUsers') return { kind: 'public', label: 'Anyone on the internet (allUsers)' };
  if (m === 'allAuthenticatedUsers') return { kind: 'public', label: 'Any Google account (allAuthenticatedUsers)' };
  if (m.startsWith('deleted:')) return { kind: 'deleted', label: m.replace(/^deleted:/, '').replace(/\?uid=.*$/, ''), email: m.replace(/^deleted:\w+:/, '').replace(/\?uid=.*$/, '') };
  const gke = m.match(/^serviceAccount:([\w.-]+)\.svc\.id\.goog\[([^/\]]+)\/([^\]]+)\]$/);
  if (gke) return { kind: 'gke', label: `GKE · ${gke[2]}/${gke[3]}`, project: gke[1], namespace: gke[2], ksa: gke[3] };
  const fed = m.match(/^principal(Set)?:\/\/iam\.googleapis\.com\/projects\/(\d+)\/locations\/global\/workloadIdentityPools\/([^/]+)\/(.+)$/);
  if (fed) return { kind: 'federated', set: !!fed[1], projectNumber: fed[2], pool: fed[3], rest: fed[4], label: `${fed[3]} · ${fed[4]}` };
  const [type, rest] = m.split(/:(.*)/s);
  if (type === 'serviceAccount') {
    const managed = /@(gcp-sa-[\w-]+|cloudservices|cloudbuild|container-engine-robot|compute-system|dataflow-service-producer-prod)\.iam\.gserviceaccount\.com$|@(cloudbuild|cloudservices)\.gserviceaccount\.com$|^service-\d+@/.test(rest);
    const project = rest.match(/@([\w-]+)\.iam\.gserviceaccount\.com$/)?.[1] || null;
    const isDefault = /-compute@developer\.gserviceaccount\.com$|@appspot\.gserviceaccount\.com$/.test(rest);
    return { kind: 'serviceAccount', email: rest, label: rest, project, managed, isDefault };
  }
  if (type === 'user' || type === 'group') return { kind: type, email: rest, label: rest };
  if (type === 'domain') return { kind: 'domain', email: rest, label: `Everyone at ${rest}` };
  return { kind: 'other', label: m };
}

/** A federated member, resolved against the pool's providers: the AWS account and role, or the repository, behind it. */
export function federatedOrigin(p, providers) {
  const mine = providers.filter((x) => x.pool_id === p.pool && (!x.project_number || x.project_number === p.projectNumber));
  const aws = mine.find((x) => x.type === 'aws'), oidc = mine.find((x) => x.type === 'oidc');
  const [attr, ...vals] = p.rest.split('/'), value = vals.join('/');
  const o = { pool: p.pool, providers: mine.map((x) => ({ id: x.provider_id, type: x.type, condition: x.attribute_condition || null, awsAccountId: x.aws_account_id || null, issuer: x.issuer || null })), whole: p.rest === '*' };
  if (aws) {
    o.cloud = 'aws'; o.awsAccountIds = mine.filter((x) => x.type === 'aws').map((x) => x.aws_account_id);
    const arn = attr === 'attribute.aws_role' || attr === 'subject' ? value : '';
    const role = arn.match(/^arn:aws[\w-]*:(?:sts|iam)::(\d{12}):(?:assumed-role|role)\/([^/]+)/);
    if (role) { o.awsAccountId = role[1]; o.awsRole = role[2]; }
    else if (attr === 'attribute.aws_account') o.awsAccountId = value;
    o.label = o.awsRole ? `AWS ${o.awsAccountId} · ${o.awsRole}` : `AWS ${o.awsAccountId || o.awsAccountIds.join(', ')} · any role`;
  } else if (oidc) {
    o.cloud = 'oidc'; o.issuer = oidc.issuer;
    const host = String(oidc.issuer || '').replace(/^https:\/\//, '');
    o.label = `${/githubusercontent/.test(host) ? 'GitHub Actions' : host}${attr === 'attribute.repository' ? ` · ${value}` : p.rest === '*' ? ' · any identity' : ` · ${value || p.rest}`}`;
  } else o.label = `${p.pool} · ${p.rest}`;
  // nothing narrows who gets in: the whole pool, and a provider with no attribute condition
  o.broad = (o.whole || (o.cloud === 'aws' && !o.awsRole)) && mine.some((x) => !x.attribute_condition);
  return o;
}

const severityRank = { high: 3, medium: 2, low: 1, info: 0 };

/**
 * @param s { org: {domain}, projects: [{project_id, ancestors}], bindings, roleDefs: Map(name -> string[]), serviceAccounts: [{email, project_id, unique_id, keys, disabled}], providers, now }
 * @returns Map(member -> { kind, roles, permissions, reach, sources, origin, risk, risk_score, risk_reasons })
 */
/** `s.keyRotateDays`: a user-managed key older than this is a medium finding (90 unless the caller says). */
export function analyzeGcp(s) {
  const keyRotateDays = s.keyRotateDays ?? 90;
  const now = s.now || Date.now();
  const projects = new Map(s.projects.map((p) => [p.project_id, p]));
  // the projects a binding reaches
  const reachOf = (b) => {
    if (b.resource_type === 'organization') return [...projects.keys()];
    if (b.resource_type === 'folder') return [...projects.values()].filter((p) => p.ancestors.includes(b.resource)).map((p) => p.project_id);
    return b.project_id && projects.has(b.project_id) ? [b.project_id] : [];
  };
  const perms = (role) => s.roleDefs.get(role) || [];
  const permSet = new Map();
  const permsOf = (role) => { if (!permSet.has(role)) permSet.set(role, new Set(perms(role))); return permSet.get(role); };
  const hasAny = (role, list) => { const p = permsOf(role); return list.some((x) => p.has(x)); };

  const out = new Map();
  const ensure = (member) => {
    if (!out.has(member)) out.set(member, { member, ...parseMember(member), bindings: [], sources: [], reasons: [] });
    return out.get(member);
  };
  for (const sa of s.serviceAccounts) Object.assign(ensure(`serviceAccount:${sa.email}`), { sa });
  for (const b of s.bindings) ensure(b.member).bindings.push(b);

  const saByEmail = new Map(s.serviceAccounts.map((x) => [x.email, x]));
  // who can become each service account
  for (const b of s.bindings) {
    const p = parseMember(b.member);
    const imp = hasAny(b.role, IMPERSONATE), act = permsOf(b.role).has(ACT_AS), mint = permsOf(b.role).has(MINT_KEY);
    if (!imp && !act && !mint) continue;
    let targets;
    if (b.resource_type === 'serviceAccount') { const email = b.resource.split('/serviceAccounts/')[1]; targets = saByEmail.has(email) ? [saByEmail.get(email)] : []; }
    else { const reach = new Set(reachOf(b)); targets = s.serviceAccounts.filter((x) => reach.has(x.project_id)); }
    for (const t of targets) {
      if (`serviceAccount:${t.email}` === b.member) continue;
      const via = p.kind === 'federated' ? 'wif' : p.kind === 'gke' ? 'gke' : imp ? 'token' : act ? 'actAs' : 'key-create';
      const src = { via, member: b.member, kind: p.kind, label: p.label, role: b.role, at: b.resource, atType: b.resource_type, wide: b.resource_type !== 'serviceAccount', conditional: !!b.condition };
      if (p.kind === 'federated') src.origin = federatedOrigin(p, s.providers);
      if (p.kind === 'gke') Object.assign(src, { namespace: p.namespace, ksa: p.ksa, gkeProject: p.project });
      ensure(`serviceAccount:${t.email}`).sources.push(src);
    }
  }

  const domain = String(s.org?.domain || '').toLowerCase();
  const external = (email) => { const d = String(email || '').split('@')[1]?.toLowerCase(); return !!domain && !!d && d !== domain && !d.endsWith(`.${domain}`) && !/gserviceaccount\.com$/.test(d); };

  for (const x of out.values()) {
    const f = (id, severity, title, detail) => x.reasons.push({ id, severity, title, detail });
    // what it can do
    const roles = [], all = new Set(), reach = new Set();
    for (const b of x.bindings) {
      const r = reachOf(b); r.forEach((pid) => reach.add(pid));
      for (const p of permsOf(b.role)) all.add(p);
      roles.push({ role: b.role, resource: b.resource, resourceType: b.resource_type, project: b.project_id || null, permissions: permsOf(b.role).size, reach: r.length,
        condition: b.condition ? (b.condition.title || b.condition.expression || 'conditional') : null, basic: /^roles\/(owner|editor|viewer)$/.test(b.role) });
    }
    roles.sort((a, c) => ({ organization: 0, folder: 1, project: 2, serviceAccount: 3 }[a.resourceType] - { organization: 0, folder: 1, project: 2, serviceAccount: 3 }[c.resourceType]) || c.permissions - a.permissions);
    const where = (b) => (b.resourceType === 'organization' ? 'the organization' : b.resourceType === 'folder' ? `folder ${b.resource.split('/')[1]}` : b.project ? `project ${b.project}` : b.resource);
    const managed = x.kind === 'serviceAccount' && x.managed;

    // findings about the identity
    if (x.kind === 'public') f('public', 'high', 'Granted to everyone', `${x.label} holds ${roles.map((r) => r.role).join(', ')}.`);
    if (x.kind === 'deleted') f('deleted', 'medium', 'Bound to a deleted identity', 'The identity is gone but its bindings stay; a new account created with the same name does not inherit them, but they are clutter to remove.');
    if ((x.kind === 'user' || x.kind === 'group') && external(x.email)) f('external', 'medium', 'Outside your domain', `${x.email} is not in ${domain}.`);
    for (const r of roles.filter((y) => y.basic && !y.condition)) {
      if (r.role === 'roles/owner') f('basic-owner', 'high', 'Owner', `Owner on ${where(r)}: every permission, including changing who has access.`);
      else if (r.role === 'roles/editor') f('basic-editor', x.sa && parseMember(x.member).isDefault ? 'high' : 'medium', parseMember(x.member).isDefault ? 'Default service account with Editor' : 'Editor', `Editor on ${where(r)}: change almost anything${parseMember(x.member).isDefault ? '. Every VM or app that runs as the default service account gets it.' : '.'}`);
    }
    const setIam = roles.filter((r) => r.role !== 'roles/owner' && [...permsOf(r.role)].some((p) => SET_IAM.test(p)) && ['organization', 'folder', 'project'].includes(r.resourceType));
    if (setIam.length) f('iam-admin', 'high', 'Can change who has access', `Can set IAM policy on ${setIam.map(where).join(', ')}.`);
    const imp = roles.filter((r) => r.resourceType !== 'serviceAccount' && (hasAny(r.role, IMPERSONATE) || permsOf(r.role).has(ACT_AS) || permsOf(r.role).has(MINT_KEY)) && !r.basic);
    if (imp.length) f('impersonate-many', 'high', 'Can become other service accounts', `${[...new Set(imp.map((r) => r.role))].join(', ')} on ${imp.map(where).join(', ')}: it can act as every service account there.`);
    // keys
    const keys = (x.sa?.keys || []).filter((k) => !k.disabled && (!k.expires || new Date(k.expires).getTime() > now));
    if (keys.length) {
      const age = (k) => Math.floor((now - new Date(k.created).getTime()) / 864e5);
      const oldest = Math.max(...keys.map(age)), forever = keys.some((k) => !k.expires || new Date(k.expires).getFullYear() > 9000);
      const strong = x.reasons.some((r) => r.severity === 'high');
      f('key', strong && forever ? 'high' : oldest > keyRotateDays ? 'medium' : 'low', `${keys.length} user-managed key${keys.length === 1 ? '' : 's'}`,
        `Oldest ${oldest} days${forever ? ', never expires' : ''}. A key is a password that works from anywhere until someone deletes it; prefer workload identity federation.`);
    }
    // where it can come from
    for (const src of x.sources) {
      if (src.via === 'wif' && src.origin?.broad) f('wif-broad', 'high', 'Any identity from a federated source', `${src.origin.label}: the pool has no attribute condition, so every identity it accepts can become this service account.`);
      if ((src.kind === 'user' || src.kind === 'group') && external(src.member.split(':')[1])) f('external-impersonator', 'high', 'Someone outside your domain can become it', `${src.label} via ${src.role}.`);
      if (src.kind === 'public') f('public-impersonator', 'high', 'Anyone can become it', `${src.label} via ${src.role}.`);
    }
    if (x.kind === 'federated') {
      x.origin = federatedOrigin(parseMember(x.member), s.providers);
      if (x.origin.broad) f('wif-broad', 'high', 'Any identity from a federated source', `${x.origin.label}: the provider has no attribute condition.`);
    }
    if (x.sa?.disabled && roles.length) f('disabled', 'low', 'Disabled but still granted roles', 'Remove the bindings or delete the service account.');
    if (roles.some((r) => r.condition)) f('conditional', 'info', 'Some roles have conditions', 'Conditions are shown but not evaluated: the analysis assumes they can be met.');
    if ((x.kind === 'group' || x.kind === 'domain') && roles.length) f('group', 'info', 'Members not expanded', 'Group and domain membership is not read; everyone in it holds these roles.');
    if (managed) f('google-managed', 'info', 'Google-managed service agent', 'Created and used by a Google service; its roles are expected.');

    // a federated identity's own origin is where it comes from
    if (x.kind === 'federated' && !x.sources.length) x.sources.push({ via: 'wif', member: x.member, kind: 'federated', label: x.origin.label, origin: x.origin, role: null, at: null, wide: false });
    if (keys.length) x.sources.unshift({ via: 'key', kind: 'key', label: `${keys.length} key${keys.length === 1 ? '' : 's'}`, keys: keys.map((k) => ({ id: k.id, created: k.created, expires: k.expires })) });

    const worst = Math.max(-1, ...x.reasons.filter((r) => !managed || r.severity === 'info').map((r) => severityRank[r.severity]));
    x.risk = managed ? 'Low' : worst >= 3 ? 'High' : worst === 2 ? 'Medium' : 'Low';
    x.risk_score = x.reasons.reduce((n, r) => n + ({ high: 50, medium: 15, low: 3, info: 0 }[r.severity]), 0) * (managed ? 0 : 1) + Math.round(Math.log10(all.size + 1) * 10);
    x.roles = roles; x.permissions = all.size; x.reach = [...reach].sort();
    x.reasons.sort((a, c) => severityRank[c.severity] - severityRank[a.severity]);
  }
  return out;
}

// ---------------------------------------------------------------- Google Cloud -> AWS
const arr = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
const GOOGLE_KEY = /^accounts\.google\.com:(sub|aud|oaud)$/i;

/** Service account unique IDs an AWS trust policy accepts Google tokens for. `any` when nothing pins it. */
export function googleTrustsOf(trust) {
  const out = [];
  for (const [i, st] of arr(trust?.Statement).entries()) {
    if (st.Effect !== 'Allow' || !arr(st.Principal?.Federated).includes('accounts.google.com')) continue;
    const ids = new Set();
    for (const kv of Object.values(st.Condition || {})) for (const [k, v] of Object.entries(kv || {})) if (GOOGLE_KEY.test(k)) for (const x of arr(v)) if (/^\d{15,25}$/.test(String(x))) ids.add(String(x));
    out.push({ statement: i, ids: [...ids], any: ids.size === 0 });
  }
  return out;
}
