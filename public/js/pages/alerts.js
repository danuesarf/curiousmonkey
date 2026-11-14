// Admin → Alerts: where alerts go, the rules that send them, and what was sent.
// Rules are evaluated by the worker every minute; instant rules post within about a minute, daily ones once a day.
import { h, get, post, api, num, ago, fmtDate, toast, modal, field, envs, envName, loadEnvironments, accountPicker } from '../lib.js';

const KIND = { slack: 'Slack', webhook: 'Webhook' };
const SEV = [['high', 'High only'], ['medium', 'Medium and high'], ['low', 'Every severity']];
const STATUS = { sent: ['b-green', 'sent'], pending: ['b-medium', 'retrying'], failed: ['b-high', 'failed'] };
// Ready-made rules, offered when there are none yet
const STARTERS = [
  { name: 'New High finding', trigger: 'finding', minSeverity: 'high' },
  { name: 'New caller from an IAM user or another account', trigger: 'change', changeKinds: ['new-caller'], minSeverity: 'high' },
  { name: 'Access key past its rotation age', trigger: 'key-age', mode: 'daily' },
  { name: 'Console password without MFA', trigger: 'console-no-mfa', mode: 'daily' },
  { name: 'Scan failed', trigger: 'scan-failed' },
];

export async function alertsPage(ctx) {
  await loadEnvironments().catch(() => {});
  const root = h('div', { class: 'stack-lg' });
  let d, accounts = [];
  async function load() {
    [d, accounts] = await Promise.all([get('/alerts'), get('/accounts').then((x) => x.items.filter((a) => a.status !== 'planned')).catch(() => [])]);
    draw();
  }
  const acctName = (id) => accounts.find((a) => a.id === id)?.name || '(removed account)';

  // ---- destinations ----
  function destinationForm(prev) {
    const name = h('input', { value: prev?.name || '', placeholder: '#sec-alerts', maxlength: 80 });
    const kind = h('select', { disabled: !!prev }, Object.entries(KIND).map(([v, l]) => h('option', { value: v, selected: prev?.kind === v }, l)));
    const url = h('input', { class: 'mono', spellcheck: 'false', autocomplete: 'off', placeholder: prev ? `Leave empty to keep ${prev.urlHint}` : 'https://hooks.slack.com/services/…' });
    const urlHint = h('span', { class: 'hint' });
    const hintFor = () => { urlHint.textContent = kind.value === 'slack'
      ? 'In Slack, add an Incoming Webhook (or a Workflow webhook) to the channel and paste its URL. It is stored encrypted and never shown again.'
      : 'Receives a JSON POST: { kind, title, rule, count, items: [{ title, subject, account, environment, severity, url }], more }. Stored encrypted and never shown again.'; };
    kind.addEventListener('change', hintFor); hintFor();
    const err = h('div', { class: 'err', role: 'alert' });
    const save = h('button', { class: 'btn primary', type: 'submit' }, prev ? 'Save' : 'Add destination');
    const m = modal(prev ? `Edit ${prev.name}` : 'Add a destination', h('form', { class: 'stack', onSubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; save.disabled = true;
      try {
        if (prev) await api('PUT', `/alerts/destinations/${prev.id}`, { name: name.value, ...(url.value.trim() ? { url: url.value } : {}) });
        else await post('/alerts/destinations', { name: name.value, kind: kind.value, url: url.value });
        m.remove(); toast(prev ? 'Destination saved' : 'Destination added. Send a test to check it.'); load();
      } catch (x) { err.textContent = x.message; save.disabled = false; }
    } }, field('Name', name, 'How rules and the log refer to it, for example the channel name.'), field('Kind', kind), h('div', { class: 'field' }, h('label', null, 'URL', url), urlHint), err,
    h('div', { class: 'actions' }, save, h('button', { class: 'btn', type: 'button', onClick: () => m.remove() }, 'Cancel'))), h('span'));
    name.focus();
  }
  async function testIt(x, btn) {
    btn.disabled = true; btn.textContent = 'Sending…';
    try {
      const r = await post(`/alerts/destinations/${x.id}/test`);
      r.ok ? toast(`Test message delivered to ${x.name}`) : toast(`${x.name}: ${r.error}`, true);
      load();
    } catch (e) { toast(e.message, true); btn.disabled = false; btn.textContent = 'Send test'; }
  }
  async function removeDest(x) {
    if (!confirm(`Remove the destination "${x.name}"?`)) return;
    try { await api('DELETE', `/alerts/destinations/${x.id}`); toast('Destination removed'); load(); } catch (e) { toast(e.message, true); }
  }

  // ---- rules ----
  function ruleForm(prev, preset = {}) {
    if (!d.destinations.length) return toast('Add a destination first: rules need somewhere to post.', true);
    const v = { mode: 'instant', minSeverity: 'high', changeKinds: [], environments: [], accounts: [], enabled: true, ...preset, ...(prev || {}) };
    const name = h('input', { value: v.name || '', maxlength: 80 });
    const trigger = h('select', { disabled: !!prev }, Object.entries(d.triggers).map(([k, t]) => h('option', { value: k, selected: v.trigger === k }, t.label)));
    const triggerHint = h('span', { class: 'hint' });
    const sev = h('select', null, SEV.map(([k, l]) => h('option', { value: k, selected: v.minSeverity === k }, l)));
    const sevField = field('Severity', sev);
    const kinds = Object.entries(d.changeKinds).map(([k, l]) => { const cb = h('input', { type: 'checkbox', value: k, checked: v.changeKinds.includes(k) }); return [cb, h('label', { class: 'row small', style: 'gap:6px' }, cb, l)]; });
    const kindsField = h('div', { class: 'field' }, h('span', { class: 'label' }, 'Which changes'), h('div', { class: 'check-grid' }, kinds.map(([, l]) => l)), h('span', { class: 'hint' }, 'None ticked means every kind.'));
    const envBoxes = envs().map((e) => { const cb = h('input', { type: 'checkbox', value: e.id, checked: v.environments.includes(e.id) }); return [cb, h('label', { class: 'row small', style: 'gap:6px' }, cb, e.name)]; });
    const envField = h('div', { class: 'field' }, h('span', { class: 'label' }, 'Environments'), h('div', { class: 'check-grid' }, envBoxes.map(([, l]) => l)), h('span', { class: 'hint' }, 'None ticked means every environment.'));
    // accounts: the shared picker; a rule naming an account that has since been removed keeps it until edited
    const pickedAccts = new Set(v.accounts);
    const acctHint = h('span', { class: 'hint' });
    const acctNote = () => { const gone = [...pickedAccts].filter((id) => !accounts.some((a) => a.id === id)).length;
      acctHint.textContent = `None picked means every account.${pickedAccts.size ? ' With environments ticked too, an account must match both.' : ''}${gone ? ` ${gone} picked account${gone === 1 ? ' was' : 's were'} removed; save to drop ${gone === 1 ? 'it' : 'them'}.` : ''}`; };
    const picker = accountPicker({ accounts, selected: pickedAccts, onChange: acctNote }); acctNote();
    const acctField = h('div', { class: 'field' }, h('span', { class: 'label' }, 'Accounts'), picker.el, picker.chips, acctHint);
    const dest = h('select', null, d.destinations.map((x) => h('option', { value: x.id, selected: v.destinationId === x.id }, `${x.name} (${KIND[x.kind]})`)));
    const mode = h('select', null, h('option', { value: 'instant', selected: v.mode === 'instant' }, 'At once (within a minute)'), h('option', { value: 'daily', selected: v.mode === 'daily' }, `Daily digest at ${d.digestAt}`));
    const show = () => {
      const t = d.triggers[trigger.value];
      triggerHint.textContent = `${t.hint}${['key-age', 'console-no-mfa'].includes(trigger.value) ? ' The first message lists everything true now; after that, only what is new.' : ' Only what happens after the rule is saved is posted.'}${trigger.value === 'key-age' ? ` Rotation age now: ${d.keyRules.rotateDays} days.` : ''}`;
      sevField.hidden = !t.severity; kindsField.hidden = trigger.value !== 'change';
      if (!prev && !name.dataset.typed) name.value = preset.name && preset.trigger === trigger.value ? preset.name : t.label;
    };
    name.addEventListener('input', () => { name.dataset.typed = '1'; });
    trigger.addEventListener('change', show); show();
    const err = h('div', { class: 'err', role: 'alert' });
    const save = h('button', { class: 'btn primary', type: 'submit' }, prev ? 'Save' : 'Add rule');
    const m = modal(prev ? `Edit ${prev.name}` : 'Add a rule', h('form', { class: 'stack', onSubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; save.disabled = true;
      const body = { name: name.value, minSeverity: sev.value, changeKinds: kinds.filter(([c]) => c.checked).map(([c]) => c.value),
        environments: envBoxes.filter(([c]) => c.checked).map(([c]) => c.value), accounts: [...pickedAccts].filter((id) => accounts.some((a) => a.id === id)),
        destinationId: dest.value, mode: mode.value };
      try {
        if (prev) await api('PUT', `/alerts/rules/${prev.id}`, body); else await post('/alerts/rules', { ...body, trigger: trigger.value });
        close(); toast(prev ? 'Rule saved' : 'Rule added. It is checked every minute.'); load();
      } catch (x) { err.textContent = x.message; save.disabled = false; }
    } }, field('When', trigger), triggerHint, sevField, kindsField, envField, acctField, field('Send to', dest), field('How often', mode, 'A digest gathers everything since the last one into one message.'), field('Name', name), err,
    h('div', { class: 'actions' }, save, h('button', { class: 'btn', type: 'button', onClick: () => close() }, 'Cancel'))), h('span'));
    // the picker listens on the document; stop when the dialog goes, however it is closed
    const close = () => m.remove();
    new MutationObserver((_, o) => { if (!m.isConnected) { picker.destroy(); o.disconnect(); } }).observe(document.body, { childList: true, subtree: true });
  }
  async function toggle(r, cb) {
    try { await api('PUT', `/alerts/rules/${r.id}`, { enabled: cb.checked }); toast(cb.checked ? `${r.name} is on. It starts from now.` : `${r.name} is off`); load(); }
    catch (e) { cb.checked = !cb.checked; toast(e.message, true); }
  }
  async function removeRule(r) {
    if (!confirm(`Remove the rule "${r.name}"? Its messages stay in the log.`)) return;
    try { await api('DELETE', `/alerts/rules/${r.id}`); toast('Rule removed'); load(); } catch (e) { toast(e.message, true); }
  }
  const filters = (r) => [
    d.triggers[r.trigger].severity && SEV.find(([k]) => k === r.minSeverity)?.[1],
    r.trigger === 'change' && (r.changeKinds.length ? r.changeKinds.map((k) => d.changeKinds[k]).join(', ') : 'every change'),
    r.environments.length ? r.environments.map(envName).join(', ') : 'every environment',
    r.accounts.length ? (r.accounts.length <= 3 ? r.accounts.map(acctName).join(', ') : `${r.accounts.length} accounts`) : null,
  ].filter(Boolean).join(' · ');

  // how long messages are kept: the alerts.keepDays setting, saved through /settings like the rest of Configuration
  function keepEl() {
    const inp = h('input', { type: 'number', min: 7, max: 3650, step: 1, value: d.keepDays, style: 'width:6em', 'aria-label': 'Keep messages for (days)' });
    const btn = h('button', { class: 'btn sm', hidden: true }, 'Save');
    inp.addEventListener('input', () => { btn.hidden = Number(inp.value) === d.keepDays; });
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try { await api('PUT', '/settings', { 'alerts.keepDays': Number(inp.value) }); toast(`Messages are kept for ${inp.value} days`); load(); }
      catch (e) { toast(e.message, true); btn.disabled = false; }
    });
    return h('label', { class: 'row small muted', style: 'gap:6px' }, 'Keep for', inp, 'days', btn);
  }

  function draw() {
    const destCard = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Destinations'), h('p', { class: 'muted small' }, 'Slack channels and webhooks. URLs are stored encrypted and never shown again.')),
        h('button', { class: 'btn', onClick: () => destinationForm() }, 'Add destination')),
      d.destinations.length ? h('div', { class: 'scroll' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'Name'), h('th', null, 'Kind'), h('th', null, 'URL'), h('th', null, 'Rules'), h('th', null, ''))),
        h('tbody', null, d.destinations.map((x) => { const tb = h('button', { class: 'btn sm' }, 'Send test'); tb.addEventListener('click', () => testIt(x, tb));
          return h('tr', null, h('td', { class: 'name' }, x.name), h('td', null, KIND[x.kind]), h('td', { class: 'mono small muted' }, x.urlHint), h('td', null, num(x.rules)),
            h('td', { class: 'actions-cell' }, tb, h('button', { class: 'btn sm', onClick: () => destinationForm(x) }, 'Edit'), h('button', { class: 'btn sm', onClick: () => removeDest(x) }, 'Remove'))); }))))
        : h('div', { class: 'empty' }, 'No destination yet. Add a Slack webhook or any HTTPS endpoint (n8n, a SIEM) to start.'));

    const ruleRows = d.rules.map((r) => {
      const cb = h('input', { type: 'checkbox', checked: r.enabled, 'aria-label': `${r.name} on` }); cb.addEventListener('change', () => toggle(r, cb));
      return h('tr', { class: r.enabled ? '' : 'muted' },
        h('td', null, h('label', { class: 'switch' }, cb, h('span'))),
        h('td', null, h('div', { class: 'name' }, r.name), h('div', { class: 'tiny muted' }, `${d.triggers[r.trigger].label} · ${filters(r)}`)),
        h('td', null, r.destinationName), h('td', { class: 'nowrap' }, r.mode === 'daily' ? `Daily, ${d.digestAt}` : 'At once'),
        h('td', { class: 'nowrap small' }, r.waiting ? `${num(r.waiting)} waiting` : '', r.waiting && r.lastSentAt ? ' · ' : '', r.lastSentAt ? `last sent ${ago(r.lastSentAt)}` : !r.waiting ? h('span', { class: 'muted' }, 'nothing sent yet') : ''),
        h('td', { class: 'actions-cell' }, h('button', { class: 'btn sm', onClick: () => ruleForm(r) }, 'Edit'), h('button', { class: 'btn sm', onClick: () => removeRule(r) }, 'Remove')));
    });
    const starters = h('div', { class: 'stack' }, h('p', { class: 'muted small' }, d.destinations.length ? 'Start from one of these:' : 'Add a destination, then start from one of these:'),
      h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px' }, STARTERS.map((s) => h('button', { class: 'btn sm', disabled: !d.destinations.length, onClick: () => ruleForm(null, s) }, s.name))));
    const ruleCard = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Rules'), h('p', { class: 'muted small' }, `Checked every minute. Matches found together go out as one message. Daily digests go out at ${d.digestAt} (${d.tz}).`)),
        h('button', { class: 'btn primary', disabled: !d.destinations.length, onClick: () => ruleForm() }, 'Add rule')),
      d.rules.length ? h('div', { class: 'scroll' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'On'), h('th', null, 'Rule'), h('th', null, 'Sends to'), h('th', null, 'How often'), h('th', null, 'Status'), h('th', null, ''))),
        h('tbody', null, ruleRows))) : h('div', { class: 'card-b' }, starters));

    const logCard = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Recent messages'), h('p', { class: 'muted small' }, 'The last 50. A message that fails is tried once more two minutes later.')),
        h('div', { class: 'row', style: 'gap:8px' }, keepEl(), h('button', { class: 'btn sm', onClick: () => load() }, 'Refresh'))),
      d.deliveries.length ? h('div', { class: 'scroll' }, h('table', { class: 'small' },
        h('thead', null, h('tr', null, h('th', null, 'When'), h('th', null, 'Rule'), h('th', null, 'Sent to'), h('th', null, 'Matches'), h('th', null, 'Result'))),
        h('tbody', null, d.deliveries.map((x) => { const [cls, label] = STATUS[x.status];
          return h('tr', null, h('td', { class: 'nowrap', title: fmtDate(x.createdAt) }, ago(x.createdAt)),
            h('td', null, x.ruleName || '(removed rule)', x.kind === 'daily' ? h('span', { class: 'badge b-neutral', style: 'margin-left:6px' }, 'digest') : null),
            h('td', null, x.destinationName || '(removed)'),
            h('td', null, x.kind === 'test' ? 'test' : h('span', null, num(x.items), x.firstTitle ? h('span', { class: 'muted' }, ` · ${x.firstTitle}${x.items > 1 ? '…' : ''}`) : '')),
            h('td', null, h('span', { class: `badge ${cls}` }, label), x.error && h('span', { class: 'muted', style: 'margin-left:6px' }, x.error), x.status === 'pending' && x.attempts ? h('span', { class: 'muted' }, ' · retrying shortly') : null)); }))))
        : h('div', { class: 'empty' }, 'Nothing sent yet.'));

    root.replaceChildren(
      h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'ADMIN · ALERTS'), h('h1', null, 'Alerts'),
        h('p', { class: 'muted' }, 'Post to Slack or a webhook when a finding appears, someone new gets into a role, a key gets old or a scan fails, so nobody has to keep the app open. ',
          h('a', { href: '#/admin/config' }, 'Risk thresholds'), ` (key rotation ${d.keyRules.rotateDays} days, unused ${d.keyRules.staleDays} days) are in Configuration.`))),
      destCard, ruleCard, d.rules.length > 0 && h('details', { class: 'card' }, h('summary', { class: 'card-b small' }, 'Starter rules'), h('div', { class: 'card-b' }, starters)), logCard);
  }

  await load();
  // the log changes as the worker sends; refresh it while the page is open and visible
  const t = setInterval(() => { if (!document.hidden && !document.querySelector('.modal-bg')) get('/alerts').then((x) => { d = x; draw(); }).catch(() => {}); }, 30_000);
  ctx.onLeave(() => clearInterval(t));
  return root;
}
