// Policy (#/policy). Every rule the tool checks is a control: listed here by what it is about, with the severity
// its findings get and whether it is on. Someone who may change settings can give a built-in control another severity,
// turn it off, and write custom controls: a rule about identities (AWS and Google Cloud) or about ways in, tested before it is saved;
// the policy can be exported as a file and imported elsewhere.
import { h, get, post, api, num, ago, toast, modal, tile, menu, searchBox, debounced, confirmDialog, syncUrl } from '../lib.js';

const SEV = [['high', 'High'], ['medium', 'Medium'], ['low', 'Low']];
const TARGET = { identity: 'Identities', 'way-in': 'Ways in (trust)' };
const EXAMPLES = {
  identity: [['Administrator roles nobody used in 90 days', 'kind = role AND policy = AdministratorAccess AND idle > 90'],
    ['Production or staging roles that can pass roles and are mostly unused', '(environment = production OR environment = staging) AND grants = iam:PassRole AND unusedpct > 80'],
    ['IAM users with a console password and no MFA', 'kind = user AND console = yes AND mfa = no'], ['Keys older than 180 days, in any cloud', 'keyage > 180'],
    ['Google Cloud service accounts with keys that reach many projects', 'cloud = gcp AND kind = serviceaccount AND keys > 0 AND reach > 5']],
  'way-in': [['An outside account or anyone into an administrator role', '(source = external OR source = public) AND has = admin'], ['CI into production without a subject condition', 'source = github,bitbucket,gitlab AND env = production AND no = sub'],
    ['Trust between accounts, not from production, never used', 'source = connected AND fromenv != production AND used = no']],
};

export async function controlsPage(ctx) {
  const P = ctx.params;
  const S = { q: P.get('q') || '' };
  let d = await get(`/controls?q=${encodeURIComponent(S.q)}`);
  const tiles = h('section', { class: 'tiles' }), list = h('div', { class: 'stack-lg' }), count = h('span', { class: 'count' });
  const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });

  async function load() {
    syncUrl({ q: S.q });
    try { d = await get(`/controls?q=${encodeURIComponent(S.q)}`); draw(); } catch (e) { toast(e.message, true); }
  }
  const search = searchBox({ value: S.q, placeholder: 'Find a control: a word, or domain:trust severity:high state:changed target:rule cloud:gcp', label: 'Search controls', onSearch: (v) => { S.q = v.trim(); load(); } });
  ctx.onLeave(search.cancel);
  const setQ = (q) => { S.q = S.q === q ? '' : q; search.value = S.q; load(); };
  const withTerm = (key, v) => { const rest = S.q.split(/\s+/).filter((t) => t && !t.toLowerCase().startsWith(`${key}:`)); if (v) rest.push(`${key}:${v}`); setQ(rest.join(' ') === S.q ? '' : rest.join(' ')); };
  const termOf = (key) => S.q.split(/\s+/).find((t) => t.toLowerCase().startsWith(`${key}:`))?.slice(key.length + 1) || '';

  async function change(x, patch, said) {
    try {
      const r = await api('PUT', `/controls/${encodeURIComponent(x.id)}`, patch);
      const n = (r.findingsChanged || 0) + (r.filed?.opened || 0) + (r.filed?.resolved || 0);
      toast(`${said}${n ? ` ${num(n)} finding${n === 1 ? '' : 's'} followed.` : ''}${x.rule ? '' : ' The rest follows within a few minutes.'}`);
      live.textContent = said;
      await load();
    } catch (e) { toast(e.message, true); await load(); }
  }
  const sevName = (s) => SEV.find(([k]) => k === s)?.[1] || s;

  function severityCell(x) {
    if (!d.canEdit) return h('span', { class: x.severity ? `badge b-${x.severity}` : 'badge b-neutral', title: x.varies || null }, x.severity ? sevName(x.severity) : 'Varies');
    if (x.source === 'custom') return h('span', { class: `badge b-${x.severity}` }, sevName(x.severity));
    const cur = x.changed && x.severity !== x.defaultSeverity ? x.severity : x.defaultSeverity;   // null = varies (built-in)
    const opt = (value, label, title) => h('button', { type: 'button', role: 'radio', 'aria-checked': String(cur === value), title, disabled: !x.enabled,
      onClick: () => { if (cur === value) return; change(x, { severity: value === x.defaultSeverity ? null : value }, `${x.name}: ${value ? sevName(value) : 'built-in severity'}.`); } }, label);
    return h('div', { class: 'seg ctl-sev', role: 'radiogroup', 'aria-label': `Severity of ${x.name}` },
      x.defaultSeverity ? null : opt(null, 'Varies', x.varies),
      ...SEV.map(([k, l]) => opt(k, l, k === x.defaultSeverity ? 'The built-in severity' : null)));
  }

  function row(x) {
    const custom = x.source === 'custom';
    const sw = d.canEdit && (() => {
      const cb = h('input', { type: 'checkbox', checked: x.enabled, 'aria-label': `${x.name}: on` });
      cb.addEventListener('change', () => (custom ? saveCustomPatch(x, { enabled: cb.checked }) : change(x, { enabled: cb.checked }, `${x.name}: turned ${cb.checked ? 'on' : 'off'}.`)));
      return h('label', { class: 'switch' }, cb, h('span'));
    })();
    return h('tr', { class: x.enabled ? null : 'ctl-off' },
      h('td', null, h('div', { class: 'name' }, x.name, x.changed && h('span', { class: 'badge b-medium', style: 'margin-left:8px', title: [x.updatedBy, x.updatedAt && ago(x.updatedAt)].filter(Boolean).join(' · ') }, 'changed here'),
        custom && h('span', { class: 'badge b-neutral', style: 'margin-left:8px' }, TARGET[x.target]),
        !custom && !x.defaultEnabled && !x.changed && h('span', { class: 'badge b-neutral', style: 'margin-left:8px', title: 'Off as shipped: turn it on if it fits how you work' }, 'optional')),
      x.what && h('div', { class: 'small muted' }, x.what),
      x.rule && h('code', { class: 'cond-line' }, x.rule),
      x.rule && h('div', { class: 'tiny muted' }, x.target === 'way-in' ? 'A rule about ways in.' : `A rule about identities in ${(x.clouds || []).map((c) => d.clouds[c] || c).join(' and ') || 'no cloud'}.`),
      !custom && !x.defaultSeverity && h('div', { class: 'tiny muted' }, `Built-in severity varies. ${x.varies}`),
      !custom && x.defaultSeverity && x.varies && h('div', { class: 'tiny muted' }, x.varies),
      h('div', { class: 'tiny muted mono' }, x.id)),
      h('td', null, severityCell(x), !custom && x.changed && x.enabled && x.severity !== x.defaultSeverity && d.canEdit && h('div', null,
        h('button', { type: 'button', class: 'link-btn tiny', onClick: () => change(x, { severity: null }, `${x.name}: back to the built-in severity.`) }, `Reset to ${x.defaultSeverity ? sevName(x.defaultSeverity).toLowerCase() : 'built-in'}`))),
      h('td', null, sw || h('span', { class: 'small' }, x.enabled ? 'On' : 'Off')),
      h('td', { class: 'num' }, x.open == null ? h('span', { class: 'muted', title: x.where }, '—')
        : x.open ? h('a', { href: x.domain === 'resource' ? `#/resources?control=${encodeURIComponent(x.id)}&exposure=all&state=open` : `#/findings?control=${encodeURIComponent(x.id)}&state=all`, title: `${num(x.undecided)} not decided` }, num(x.open)) : h('span', { class: 'muted' }, '0')),
      h('td', { class: 'small muted' }, x.where),
      h('td', { class: 'actions-cell' }, custom && d.canEdit ? [h('button', { class: 'btn sm', onClick: () => editor(x) }, 'Edit'), h('button', { class: 'btn sm', onClick: () => remove(x) }, 'Delete')]
        : x.rule && d.canEdit ? h('button', { class: 'btn sm', title: 'Start a custom control from this rule', onClick: () => editor(null, x) }, 'Copy') : null));
  }
  async function saveCustomPatch(x, patch) {
    try {
      await api('PUT', `/controls/${encodeURIComponent(x.id)}`, { name: x.name, description: x.what, target: x.target, rule: x.rule, severity: x.severity, remediation: x.fix, enabled: x.enabled, ...patch });
      toast(`${x.name}: saved.`); await load();
    } catch (e) { toast(e.message, true); await load(); }
  }
  async function remove(x) {
    if (!(await confirmDialog({ title: `Delete “${x.name}”?`, message: x.open ? `Its ${num(x.open)} open finding${x.open === 1 ? '' : 's'} will be closed. Decisions made on them stay in the audit log.` : 'It has no open findings.', confirmLabel: 'Delete', danger: true }))) return;
    try { await api('DELETE', `/controls/${encodeURIComponent(x.id)}`); toast('Control deleted'); await load(); } catch (e) { toast(e.message, true); }
  }

  // ---- a custom control: what it applies to, the rule (tested as it is typed), severity, and what to tell the reviewer
  function editor(x = null, from = null) {
    const f = { target: (x || from)?.target || 'identity' };
    const nameIn = h('input', { class: 'input', value: x?.name || (from ? `${from.name} (ours)` : ''), maxlength: 120, placeholder: 'Administrator roles nobody uses', 'aria-label': 'Name' });
    const ruleIn = h('textarea', { class: 'input mono', rows: 3, spellcheck: 'false', 'aria-label': 'Rule', placeholder: '(environment = production OR environment = staging) AND kind = role AND idle > 90' }, (x || from)?.rule || '');
    const sevIn = h('select', { 'aria-label': 'Severity' }, SEV.map(([k, l]) => h('option', { value: k, selected: ((x || from)?.severity || 'medium') === k }, l)));
    const whatIn = h('textarea', { class: 'input', rows: 2, maxlength: 1000, 'aria-label': 'What it means', placeholder: 'Shown on each finding: why this matters here.' }, (x || from)?.what || '');
    const fixIn = h('textarea', { class: 'input', rows: 2, maxlength: 1000, 'aria-label': 'What to do', placeholder: 'Shown as the suggestion: what the owner should do.' }, (x || from)?.fix || '');
    const result = h('div', { class: 'ctl-test', 'aria-live': 'polite' }), keys = h('div', { class: 'ctl-keys' }), examples = h('div', { class: 'ctl-examples' });
    const err = h('p', { class: 'small tm-bad', hidden: true });
    let seq = 0;
    const test = async () => {
      const rule = ruleIn.value.trim(), mine = ++seq;
      if (!rule) { result.replaceChildren(h('p', { class: 'small muted' }, 'Write a rule to see what it matches now.')); return; }
      try {
        const r = await post('/controls/test', { target: f.target, rule });
        if (mine !== seq) return;
        if (r.errors.length) { result.replaceChildren(...r.errors.map((e) => h('p', { class: 'small tm-bad', style: 'margin:0' }, e))); return; }
        const what = f.target === 'identity' ? 'identities' : 'ways in';
        const per = r.byCloud && (r.clouds || []).length > 1 ? ` (${r.clouds.map((c) => `${d.clouds[c]} ${num(r.byCloud[c])}`).join(' · ')})` : r.clouds?.length === 1 && f.target === 'identity' ? ` (${d.clouds[r.clouds[0]]} only)` : '';
        result.replaceChildren(h('p', { class: 'small', style: 'margin:0 0 4px' }, h('b', null, `Matches ${num(r.total)} `), r.of != null ? `of ${num(r.of)} ${what} now${per}.` : `${what} now.`,
          r.total > r.items.length ? ` The first ${r.items.length}:` : '', r.ms != null && h('span', { class: 'muted tiny' }, `  ${num(r.ms)} ms`)),
        r.items.length ? h('ul', { class: 'plain small ctl-matches' }, r.items.map((i) => h('li', null, i.cloud === 'gcp' ? h('span', null, i.name) : h('a', { href: `#/identities/${i.id}`, target: '_blank', rel: 'noopener' }, i.name),
          h('span', { class: 'muted' }, ` · ${i.cloud === 'gcp' ? 'Google Cloud · ' : ''}${i.account}${i.risk ? ` · ${i.risk}` : ''}`)))) : null);
      } catch (e) { if (mine === seq) result.replaceChildren(h('p', { class: 'small tm-bad' }, e.message)); }
    };
    const later = debounced(test, 200);
    ruleIn.addEventListener('input', later);
    const drawHelp = () => {
      keys.replaceChildren(...Object.entries(d.keys[f.target]).map(([k, v]) => h('button', { type: 'button', class: 'ctl-key',
        title: `${v.help}${v.clouds ? ` · ${v.clouds.map((c) => d.clouds[c]).join(' and ')}` : ''}`,
        onClick: () => { ruleIn.value = `${ruleIn.value.trimEnd()}${ruleIn.value.trim() ? ' AND ' : ''}${k} = `; ruleIn.focus(); } }, k, v.clouds && v.clouds.length === 1 ? h('sup', null, v.clouds[0]) : null)));
      examples.replaceChildren(h('span', { class: 'tiny muted' }, 'Examples: '), ...EXAMPLES[f.target].map(([label, rule]) => h('button', { type: 'button', class: 'link-btn tiny', title: rule, onClick: () => { ruleIn.value = rule; if (!nameIn.value) nameIn.value = label; test(); } }, label)));
    };
    const targetSeg = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'Applies to' }, ...Object.entries(TARGET).map(([k, l]) => h('button', { type: 'button', role: 'radio', 'aria-checked': String(f.target === k), disabled: !!x,
      onClick: (e) => { f.target = k; for (const b of e.currentTarget.parentElement.children) b.setAttribute('aria-checked', String(b === e.currentTarget)); drawHelp(); test(); } }, l)));
    const save = h('button', { class: 'btn primary', onClick: async () => {
      err.hidden = true; save.disabled = true;
      const body = { name: nameIn.value.trim(), target: f.target, rule: ruleIn.value.trim(), severity: sevIn.value, description: whatIn.value.trim() || null, remediation: fixIn.value.trim() || null, enabled: x ? x.enabled : true };
      try {
        const r = x ? await api('PUT', `/controls/${encodeURIComponent(x.id)}`, body) : await post('/controls', body);
        bg.remove();
        toast(r.filed ? `Saved. ${num(r.filed.opened)} finding${r.filed.opened === 1 ? '' : 's'} opened${r.filed.resolved ? `, ${num(r.filed.resolved)} closed` : ''}${r.filed.gcpChanged ? `; ${num(r.filed.gcpChanged)} Google Cloud identit${r.filed.gcpChanged === 1 ? 'y' : 'ies'} updated` : ''}.` : 'Saved. Its findings show on the Trust map now, and in the inbox within a minute.');
        await load();
      } catch (e) { save.disabled = false; err.hidden = false; err.textContent = e.message; }
    } }, x ? 'Save' : 'Add control');
    const bg = modal(x ? `Edit “${x.name}”` : 'Add a custom control', h('div', { class: 'stack' },
      h('p', { class: 'small muted', style: 'margin:0' }, 'A rule that is checked like the built-in ones: whatever it matches gets a finding with this severity, and the finding closes when it no longer matches.', from ? ` Started from “${from.name}”.` : ''),
      h('label', { class: 'field' }, h('span', null, 'Name'), nameIn),
      h('div', { class: 'field' }, h('span', null, 'Applies to'), targetSeg, x && h('span', { class: 'tiny muted' }, 'Fixed once the control exists.')),
      h('label', { class: 'field' }, h('span', null, 'Rule'), ruleIn),
      h('p', { class: 'tiny muted', style: 'margin:-6px 0 0' }, 'Terms are key = value, joined with AND, OR and NOT, grouped with brackets. Operators: =, !=, >, >=, <, <=. A key can be used more than once. * is a wildcard; a comma list means any of them (with != none of them). ',
        'For identities, a rule covers a cloud when every key it uses exists there; keys marked aws or gcp exist on one only.'),
      keys, examples, result,
      h('label', { class: 'field' }, h('span', null, 'Severity'), sevIn),
      h('label', { class: 'field' }, h('span', null, 'What it means'), whatIn),
      h('label', { class: 'field' }, h('span', null, 'What to do'), fixIn), err),
    h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: () => bg.remove() }, 'Cancel'), save));
    bg.querySelector('.modal')?.classList.add('wide');
    drawHelp(); test(); nameIn.focus();
  }

  // ---- import a policy file: read it, show what it would do, then do it
  function importer() {
    const file = h('input', { type: 'file', accept: '.json,application/json', 'aria-label': 'Policy file' });
    const replace = h('input', { type: 'checkbox' });
    const out = h('div', { class: 'ctl-test', 'aria-live': 'polite' }, h('p', { class: 'small muted', style: 'margin:0' }, 'Choose a policy file exported from this or another workspace.'));
    let policy = null;
    const apply = h('button', { class: 'btn primary', disabled: true, onClick: async () => {
      apply.disabled = true;
      try {
        const r = await post('/controls/import', { policy, replace: replace.checked });
        bg.remove();
        toast(`Imported: ${num(r.created)} added, ${num(r.updated)} updated, ${num(r.overrides)} built-in change${r.overrides === 1 ? '' : 's'}${r.removed ? `, ${num(r.removed)} removed` : ''}${r.skipped.length ? `, ${num(r.skipped.length)} skipped` : ''}.`);
        await load();
      } catch (e) { apply.disabled = false; toast(e.message, true); }
    } }, 'Import');
    const dry = async () => {
      apply.disabled = true;
      if (!policy) return;
      try {
        const r = await post('/controls/import', { policy, dryRun: true, replace: replace.checked });
        const line = (label, names) => (names.length ? h('p', { class: 'small', style: 'margin:0 0 2px' }, h('b', null, `${label} ${num(names.length)}: `), names.slice(0, 12).join(', '), names.length > 12 ? '…' : '') : null);
        out.replaceChildren(
          h('p', { class: 'small', style: 'margin:0 0 4px' }, h('b', null, 'This file would: '), `change ${num(r.overrides)} built-in control${r.overrides === 1 ? '' : 's'}`, r.reset ? `, reset ${num(r.reset)} to built-in` : '', '.'),
          line('Add', r.names.create), line('Update', r.names.update), line('Remove', r.names.remove),
          ...r.skipped.map((x) => h('p', { class: 'small tm-bad', style: 'margin:0' }, `Skipped “${x.what}”: ${x.why}`)));
        apply.disabled = !(r.overrides + r.created + r.updated + r.removed + r.reset);
      } catch (e) { out.replaceChildren(h('p', { class: 'small tm-bad', style: 'margin:0' }, e.message)); }
    };
    file.addEventListener('change', async () => {
      policy = null;
      const fl = file.files[0];
      if (!fl) return;
      if (fl.size > 200_000) { out.replaceChildren(h('p', { class: 'small tm-bad', style: 'margin:0' }, 'That file is too large to be a policy file.')); return; }
      try { policy = JSON.parse(await fl.text()); } catch { out.replaceChildren(h('p', { class: 'small tm-bad', style: 'margin:0' }, 'That file is not JSON.')); return; }
      dry();
    });
    replace.addEventListener('change', dry);
    const bg = modal('Import a policy', h('div', { class: 'stack' },
      h('p', { class: 'small muted', style: 'margin:0' }, 'Custom controls are matched by name: new names are added, existing ones updated. Built-in controls take the severity and on/off of the file. Nothing changes until you press Import.'),
      file, h('label', { class: 'tm2-check' }, replace, h('span', null, 'Replace: also remove custom controls and reset built-in changes that the file does not hold')), out),
    h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: () => bg.remove() }, 'Cancel'), apply));
  }

  function draw() {
    const s = d.summary;
    tiles.replaceChildren(
      tile('Controls', num(s.builtin + s.custom), `${num(s.builtin)} built in · ${num(s.custom)} custom`),
      tile('Changed here', num(s.changed), 'a severity set, or turned off', { pressed: S.q === 'state:changed source:builtin', onClick: () => setQ('state:changed source:builtin') }),
      tile('Turned off', num(s.off), 'make no findings', { pressed: S.q === 'state:off', onClick: () => setQ('state:off'), bad: false }),
      tile('Custom', num(s.custom), 'rules written here', { pressed: S.q === 'source:custom', onClick: () => setQ('source:custom') }));
    drawMenus();
    count.textContent = d.items.length === d.total ? `${num(d.total)} controls` : `${num(d.items.length)} of ${num(d.total)} controls`;
    const groups = Object.entries(d.domains).map(([k, label]) => [k, label, d.items.filter((x) => x.domain === k)]).filter(([, , xs]) => xs.length);
    list.replaceChildren(...(groups.length ? groups.map(([k, label, xs]) => h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, label), h('p', { class: 'muted small', style: 'margin:2px 0 0' }, `${num(xs.length)} control${xs.length === 1 ? '' : 's'}${xs.some((x) => !x.enabled) ? ` · ${num(xs.filter((x) => !x.enabled).length)} off` : ''}`)),
        k === 'custom' && d.canEdit && h('button', { class: 'btn sm', onClick: () => editor() }, 'Add custom control')),
      h('div', { class: 'table-wrap' }, h('table', { class: 'table ctl-table' },
        h('thead', null, h('tr', null, h('th', null, 'Control'), h('th', null, 'Severity'), h('th', null, 'On'), h('th', { class: 'num' }, 'Open findings'), h('th', null, 'Shows in'), h('th'))),
        h('tbody', null, xs.map(row))))))
      : [h('div', { class: 'empty' }, S.q ? 'No control matches this search.' : 'No controls.')]));
  }

  const domainMenu = () => menu(`Domain${termOf('domain') ? `: ${d.domains[termOf('domain')] || termOf('domain')}` : ''} ▾`,
    [['Every domain', () => withTerm('domain', ''), { checked: !termOf('domain') }], ...Object.entries(d.domains).map(([k, l]) => [l, () => withTerm('domain', k), { checked: termOf('domain') === k }])], { align: 'start', btnClass: 'btn' });
  const sevMenu = () => menu(`Severity${termOf('severity') ? `: ${termOf('severity')}` : ''} ▾`,
    [['Any severity', () => withTerm('severity', ''), { checked: !termOf('severity') }], ...[...SEV, ['varies', 'Varies']].map(([k, l]) => [l, () => withTerm('severity', k), { checked: termOf('severity') === k }])], { align: 'start', btnClass: 'btn' });
  const menus = h('span', { class: 'row', style: 'gap:8px' });
  const drawMenus = () => menus.replaceChildren(domainMenu(), sevMenu());

  draw();
  return h('div', { class: 'stack-lg controls-page' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'REVIEW · POLICY'), h('h1', null, 'What is checked, and how serious it is'),
      h('p', { class: 'muted', style: 'max-width:860px' }, 'Every rule the tool checks is a control. Set the severity its findings get, turn off what does not apply to you, and add your own rules. ',
        d.canEdit ? 'A change moves the open findings at once where it can; risk scores and the rest follow when the accounts are analysed again, within a few minutes.' : 'You can read the policy; changing it needs the settings permission.')),
    h('div', { class: 'actions' }, menu('Export ▾', [['The policy, to import elsewhere (JSON)', '/api/controls/export'], ['This list (CSV)', () => { location.href = `/api/controls.csv?q=${encodeURIComponent(S.q)}`; }]], { btnClass: 'btn' }),
      d.canEdit && h('button', { class: 'btn', onClick: () => importer() }, 'Import…'),
      d.canEdit && h('button', { class: 'btn primary', onClick: () => editor() }, 'Add custom control'))),
    tiles,
    h('section', { class: 'card' }, h('div', { class: 'filters' }, search, menus, count)),
    list, live);
}
