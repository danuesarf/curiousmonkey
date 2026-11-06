import { h, get, post, api, num, ago, fmtDate, toast, copy, field, busy } from '../lib.js';
import { session, go } from '../main.js';

const REGIONS = ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-northeast-1', 'ap-south-1'];
const STATUS = { connected: 'b-green', pending: 'b-medium', error: 'b-high' };

export async function accountsPage(ctx) {
  const { items } = await get('/accounts');
  const can = (p) => session.user.permissions.includes(p);
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('h1', null, 'Cloud accounts'), h('p', { class: 'muted' }, 'Each account gets a read-only scanner role that can read IAM and CloudTrail Event History, and is explicitly denied your data.')),
      can('accounts') && h('a', { class: 'btn primary', href: '#/accounts/new' }, 'Connect an AWS account')),
    items.length ? items.map((a) => accountCard(a, ctx, can)) : h('div', { class: 'card empty' }, 'No accounts connected yet.'));
}

function accountCard(a, ctx, can) {
  const dataBox = h('div', { class: 'card-b' });
  const loadData = async () => {
    const r = await get(`/accounts/${a.id}/data-events`);
    dataBox.replaceChildren(r.items.length ? h('div', { class: 'stack' }, h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Source'), h('th', null, 'Resource type'), h('th', null, 'Covers'), h('th', null, 'Read/write'))),
      h('tbody', null, r.items.map((x) => h('tr', null, h('td', null, x.source_name, h('div', { class: 'tiny muted' }, x.source_type)), h('td', { class: 'mono small' }, x.resource_type), h('td', { class: 'mono small' }, x.arn_patterns.join(', ')), h('td', null, x.read_write)))))),
      h('p', { class: 'small muted' }, r.note)) : h('p', { class: 'muted' }, 'No data event logging found. Without it, object-level and item-level permissions can never be verified.'));
  };
  const det = h('details', null, h('summary', { class: 'btn sm' }, 'Buckets and resources with data events'), dataBox);
  det.addEventListener('toggle', () => { if (det.open) loadData(); });
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('h2', null, a.name), h('span', { class: `badge ${STATUS[a.status]}` }, a.status), h('span', { class: 'small muted mono' }, `${a.account_id} · ${a.environment}`)),
      h('div', { class: 'row' }, can('scan') && h('button', { class: 'btn sm', onClick: async (e) => { try { await post(`/accounts/${a.id}/scan`); toast('Scan queued'); go('#/scans'); } catch (x) { toast(x.message, true); } } }, 'Scan now'),
        can('accounts') && a.status !== 'connected' && h('button', { class: 'btn sm primary', onClick: async () => { try { await post(`/accounts/${a.id}/verify`); toast('Checking the connection…'); go('#/scans'); } catch (x) { toast(x.message, true); } } }, 'Verify connection'),
        can('accounts') && h('button', { class: 'btn sm danger', onClick: async () => { if (confirm(`Remove ${a.name} and all of its scan history?`)) { await api('DELETE', `/accounts/${a.id}`); ctx.reload(); } } }, 'Remove'))),
    a.status === 'error' && h('div', { class: 'card-b' }, h('div', { class: 'alert bad' }, a.status_detail?.message || 'The scanner role could not be assumed.')),
    h('div', { class: 'card-b stack' },
      h('dl', { class: 'kv' }, h('dt', null, 'Scanner role'), h('dd', { class: 'mono small' }, a.role_arn), h('dt', null, 'Regions'), h('dd', null, a.regions.join(', ')),
        h('dt', null, 'Roles found'), h('dd', null, num(a.roles)), h('dt', null, 'Last scan'), h('dd', null, a.last_scan_at ? `${fmtDate(a.last_scan_at)} (${ago(a.last_scan_at)})` : 'never')),
      a.checkpoints.length > 0 && h('div', null, h('h3', null, 'Stored history'), h('p', { class: 'small muted' }, 'Each daily scan continues from the newest stored event. It never re-reads history that is already saved.'),
        h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Region'), h('th', null, 'History starts'), h('th', null, 'Stored up to'), h('th', null, 'Events read'), h('th', null, 'Gap'))),
          h('tbody', null, a.checkpoints.map((c) => h('tr', null, h('td', { class: 'mono small' }, c.region), h('td', { class: 'small' }, fmtDate(c.first)), h('td', { class: 'small' }, fmtDate(c.last)), h('td', null, num(c.events)),
            h('td', null, c.gap ? h('span', { class: 'badge b-medium', title: 'The worker was down longer than CloudTrail keeps history, so some days were never read.' }, 'gap') : 'none'))))))),
      det));
}

export async function newAccountPage(ctx) {
  const st = { step: 1, name: '', accountId: '', environment: 'production', regions: new Set(['ap-southeast-3']), roleName: 'CuriousMonkeyScanner', account: null, snippets: null, tf: 'terraform' };
  const body = h('div', { class: 'stack-lg' });
  const render = () => { body.replaceChildren(stepper(), st.step === 1 ? step1() : st.step === 2 ? step2() : step3()); };
  const stepper = () => h('ol', { class: 'row', style: null }, ['Account details', 'Deploy the scanner role', 'Verify and first scan'].map((l, i) => h('li', { class: 'row', 'aria-current': st.step === i + 1 ? 'step' : null }, h('span', { class: `badge ${st.step > i + 1 ? 'b-green' : st.step === i + 1 ? 'b-banana' : 'b-neutral'}` }, i + 1), h('span', { class: st.step === i + 1 ? 'name' : 'muted' }, l))));

  const step1 = () => {
    const name = h('input', { value: st.name, required: true, placeholder: 'e.g. payments-prod' }), id = h('input', { value: st.accountId, inputmode: 'numeric', maxlength: '12', placeholder: '12 digits' });
    const env = h('select', null, ['production', 'staging', 'development', 'sandbox'].map((e) => h('option', { value: e, selected: e === st.environment }, e)));
    const rn = h('input', { value: st.roleName });
    const err = h('div', { class: 'err', role: 'alert' });
    return h('form', { class: 'card', onSubmit: async (e) => {
      e.preventDefault(); err.textContent = '';
      Object.assign(st, { name: name.value, accountId: id.value, environment: env.value, roleName: rn.value });
      try { st.account = await post('/accounts', { name: st.name, accountId: st.accountId, environment: st.environment, regions: [...st.regions], roleName: st.roleName });
        st.snippets = await get(`/onboarding/snippets?roleName=${encodeURIComponent(st.roleName)}`); st.step = 2; render(); } catch (x) { err.textContent = x.message; }
    } }, h('div', { class: 'card-b stack' }, field('Name', name), field('AWS account ID', id), field('Environment', env),
      h('fieldset', { class: 'field' }, h('legend', { class: 'label' }, 'Regions to read CloudTrail from'), h('div', { class: 'pill-bar' }, REGIONS.map((r) => { const b = h('button', { type: 'button', class: 'chip', 'aria-pressed': st.regions.has(r) }, r); b.addEventListener('click', () => { st.regions.has(r) ? st.regions.delete(r) : st.regions.add(r); b.setAttribute('aria-pressed', st.regions.has(r)); }); return b; })),
        h('span', { class: 'hint' }, 'Event History is kept per region. Pick every region where this account runs workloads.')),
      field('Scanner role name', rn, 'You can keep the default.'), err, h('div', null, h('button', { class: 'btn primary', type: 'submit' }, 'Continue'))));
  };

  const step2 = () => {
    const s = st.snippets; const text = st.tf === 'terraform' ? s.terraform : s.cloudformation;
    return h('div', { class: 'stack' },
      !s.principalArn && h('div', { class: 'alert warn' }, 'SCANNER_PRINCIPAL_ARN is not set on the server, so the trust policy below has a placeholder. Set it to the role your worker runs as, then reload.'),
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, `Deploy this in account ${st.account.account_id}`),
        h('div', { class: 'tabs', role: 'tablist' }, [['terraform', 'Terraform'], ['cloudformation', 'CloudFormation']].map(([k, l]) => h('button', { role: 'tab', 'aria-selected': st.tf === k, onClick: () => { st.tf = k; render(); } }, l)))),
        h('div', { class: 'card-b stack' }, h('pre', null, text), h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => copy(text) }, 'Copy'),
          h('span', { class: 'small muted' }, 'ExternalId: ', h('code', null, s.externalId))))),
      h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, h('h3', null, 'What this role can and cannot do'),
        h('p', { class: 'small' }, 'It can list IAM roles and policies, run Access Advisor, and read CloudTrail Event History. It is explicitly denied reading S3 objects, DynamoDB items, secrets, parameters, KMS decrypt and Lambda invoke, so even a leaked scanner credential cannot read your data.'))),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onClick: () => { st.step = 3; render(); } }, 'I deployed it. Verify'), h('button', { class: 'btn', onClick: () => { st.step = 1; render(); } }, 'Back')));
  };

  const step3 = () => {
    const out = h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Curious Monkey will assume the role, list IAM roles, and start the first scan in the background. The first scan reads the last 90 days of Event History and can take a while.'));
    const btn = h('button', { class: 'btn primary' }, 'Verify and start first scan');
    btn.addEventListener('click', busy(btn, async () => {
      btn.textContent = 'Checking…';
      await post(`/accounts/${st.account.id}/verify`);
      out.replaceChildren(h('span', { class: 'spin' }), ' Waiting for the worker to assume the role…');
      for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const a = (await get('/accounts')).items.find((x) => x.id === st.account.id);
        if (a.status === 'connected') { out.replaceChildren(h('div', { class: 'alert ok' }, `Connected. ${a.roles} roles found. The first scan keeps running in the background.`), h('a', { class: 'btn primary', href: '#/scans' }, 'Watch scan progress')); return; }
        if (a.status === 'error') { out.replaceChildren(h('div', { class: 'alert bad' }, a.status_detail?.message || 'Could not assume the role.'), h('p', { class: 'small muted' }, 'Check the role ARN, the trust policy principal and the ExternalId, then try again.')); return; }
      }
      out.replaceChildren(h('div', { class: 'alert warn' }, 'Still waiting. Is a worker running? Check Scan activity.'), h('a', { class: 'btn', href: '#/scans' }, 'Open scan activity'));
    }));
    return h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, out, h('div', { class: 'row' }, btn, h('button', { class: 'btn', onClick: () => { st.step = 2; render(); } }, 'Back'))));
  };
  render();
  return h('div', { class: 'stack-lg' }, h('header', { class: 'head' }, h('div', null, h('div', { class: 'crumbs' }, h('a', { href: '#/accounts' }, 'Cloud accounts'), ' / New'), h('h1', null, 'Connect an AWS account'))), body);
}
