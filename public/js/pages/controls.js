// Admin → Manage policy. Every rule the tool checks is a control: listed here by what it is about, with the severity
// its findings get and whether it is on. Someone who may change settings can give a built-in control another severity,
// turn it off, and write custom controls: a rule about roles and IAM users, or about ways in, tested before it is saved.
import { h, get, post, api, num, ago, toast, modal, tile, menu, searchBox, debounced, confirmDialog, syncUrl } from '../lib.js';

const SEV = [['high', 'High'], ['medium', 'Medium'], ['low', 'Low']];
const TARGET = { identity: 'Roles and IAM users', 'way-in': 'Ways in (trust)' };
const EXAMPLES = {
  identity: [['Administrator roles nobody used in 90 days', 'kind:role policy:AdministratorAccess idle:>90'], ['Production roles that can pass roles and are mostly unused', 'env:production grants:iam:PassRole unusedpct:>80'],
    ['IAM users with a console password and no MFA', 'kind:user console:yes mfa:no'], ['Access keys older than 180 days', 'keyage:>180']],
  'way-in': [['An outside account into an administrator role', 'source:external has:admin'], ['CI into production without a subject condition', 'source:github,bitbucket,gitlab env:production no:sub'],
    ['Trust between accounts that was never used', 'source:connected used:no']],
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
  const search = searchBox({ value: S.q, placeholder: 'Find a control: a word, or domain:trust severity:high state:changed', label: 'Search controls', onSearch: (v) => { S.q = v.trim(); load(); } });
  ctx.onLeave(search.cancel);
  const setQ = (q) => { S.q = S.q === q ? '' : q; search.value = S.q; load(); };
  const withTerm = (key, v) => { const rest = S.q.split(/\s+/).filter((t) => t && !t.toLowerCase().startsWith(`${key}:`)); if (v) rest.push(`${key}:${v}`); setQ(rest.join(' ') === S.q ? '' : rest.join(' ')); };
  const termOf = (key) => S.q.split(/\s+/).find((t) => t.toLowerCase().startsWith(`${key}:`))?.slice(key.length + 1) || '';

  async function change(x, patch, said) {
    try {
      const r = await api('PUT', `/controls/${encodeURIComponent(x.id)}`, patch);
      toast(`${said}${r.findingsChanged ? ` ${num(r.findingsChanged)} open finding${r.findingsChanged === 1 ? '' : 's'} followed.` : ''} The rest follows within a few minutes.`);
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
        custom && h('span', { class: 'badge b-neutral', style: 'margin-left:8px' }, TARGET[x.target])),
      x.what && h('div', { class: 'small muted' }, x.what),
      custom && h('code', { class: 'cond-line' }, x.rule),
      !custom && !x.defaultSeverity && h('div', { class: 'tiny muted' }, `Built-in severity varies. ${x.varies}`),
      !custom && x.defaultSeverity && x.varies && h('div', { class: 'tiny muted' }, x.varies),
      h('div', { class: 'tiny muted mono' }, x.id)),
      h('td', null, severityCell(x), !custom && x.changed && x.enabled && x.severity !== x.defaultSeverity && d.canEdit && h('div', null,
        h('button', { type: 'button', class: 'link-btn tiny', onClick: () => change(x, { severity: null }, `${x.name}: back to the built-in severity.`) }, `Reset to ${x.defaultSeverity ? sevName(x.defaultSeverity).toLowerCase() : 'built-in'}`))),
      h('td', null, sw || h('span', { class: 'small' }, x.enabled ? 'On' : 'Off')),
      h('td', { class: 'num' }, x.open == null ? h('span', { class: 'muted', title: x.where }, '—')
        : x.open ? h('a', { href: `#/findings?control=${encodeURIComponent(x.id)}&state=all`, title: `${num(x.undecided)} not decided` }, num(x.open)) : h('span', { class: 'muted' }, '0')),
      h('td', { class: 'small muted' }, x.where),
      h('td', { class: 'actions-cell' }, custom && d.canEdit ? [h('button', { class: 'btn sm', onClick: () => editor(x) }, 'Edit'), h('button', { class: 'btn sm', onClick: () => remove(x) }, 'Delete')] : null));
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
  function editor(x = null) {
    const f = { target: x?.target || 'identity' };
    const nameIn = h('input', { class: 'input', value: x?.name || '', maxlength: 120, placeholder: 'Administrator roles nobody uses', 'aria-label': 'Name' });
    const ruleIn = h('textarea', { class: 'input mono', rows: 3, spellcheck: 'false', 'aria-label': 'Rule', placeholder: 'key:value key:value …' }, x?.rule || '');
    const sevIn = h('select', { 'aria-label': 'Severity' }, SEV.map(([k, l]) => h('option', { value: k, selected: (x?.severity || 'medium') === k }, l)));
    const whatIn = h('textarea', { class: 'input', rows: 2, maxlength: 1000, 'aria-label': 'What it means', placeholder: 'Shown on each finding: why this matters here.' }, x?.what || '');
    const fixIn = h('textarea', { class: 'input', rows: 2, maxlength: 1000, 'aria-label': 'What to do', placeholder: 'Shown as the suggestion: what the owner should do.' }, x?.fix || '');
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
        result.replaceChildren(h('p', { class: 'small', style: 'margin:0 0 4px' }, h('b', null, `Matches ${num(r.total)} `), r.of != null ? `of ${num(r.of)} ${what} now.` : `${what} now.`,
          r.total > r.items.length ? ` The first ${r.items.length}:` : ''),
        r.items.length ? h('ul', { class: 'plain small ctl-matches' }, r.items.map((i) => h('li', null, h('a', { href: `#/identities/${i.id}`, target: '_blank', rel: 'noopener' }, i.name), h('span', { class: 'muted' }, ` · ${i.account}${i.risk ? ` · ${i.risk}` : ''}`)))) : null);
      } catch (e) { if (mine === seq) result.replaceChildren(h('p', { class: 'small tm-bad' }, e.message)); }
    };
    const later = debounced(test, 350);
    ruleIn.addEventListener('input', later);
    const drawHelp = () => {
      keys.replaceChildren(...Object.entries(d.keys[f.target]).map(([k, help]) => h('button', { type: 'button', class: 'ctl-key', title: help,
        onClick: () => { ruleIn.value = `${ruleIn.value.trimEnd()}${ruleIn.value.trim() ? ' ' : ''}${k}:`; ruleIn.focus(); } }, k)));
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
        toast(r.filed ? `Saved. ${num(r.filed.opened)} finding${r.filed.opened === 1 ? '' : 's'} opened${r.filed.resolved ? `, ${num(r.filed.resolved)} closed` : ''}.` : 'Saved. Its findings show on the Trust map now, and in the inbox within a minute.');
        await load();
      } catch (e) { save.disabled = false; err.hidden = false; err.textContent = e.message; }
    } }, x ? 'Save' : 'Add control');
    const bg = modal(x ? `Edit “${x.name}”` : 'Add a custom control', h('div', { class: 'stack' },
      h('p', { class: 'small muted', style: 'margin:0' }, 'A rule that is checked like the built-in ones: whatever it matches gets a finding with this severity, and the finding closes when it no longer matches.'),
      h('label', { class: 'field' }, h('span', null, 'Name'), nameIn),
      h('div', { class: 'field' }, h('span', null, 'Applies to'), targetSeg, x && h('span', { class: 'tiny muted' }, 'Fixed once the control exists.')),
      h('label', { class: 'field' }, h('span', null, 'Rule'), ruleIn),
      h('p', { class: 'tiny muted', style: 'margin:-6px 0 0' }, 'key:value terms. A space means and; a comma inside a value means or; a leading - means not; * is a wildcard; numbers take > and < (idle:>90).'),
      keys, examples, result,
      h('label', { class: 'field' }, h('span', null, 'Severity'), sevIn),
      h('label', { class: 'field' }, h('span', null, 'What it means'), whatIn),
      h('label', { class: 'field' }, h('span', null, 'What to do'), fixIn), err),
    h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: () => bg.remove() }, 'Cancel'), save));
    bg.querySelector('.modal')?.classList.add('wide');
    drawHelp(); test(); nameIn.focus();
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
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'ADMIN · MANAGE POLICY'), h('h1', null, 'What is checked, and how serious it is'),
      h('p', { class: 'muted', style: 'max-width:860px' }, 'Every rule the tool checks is a control. Set the severity its findings get, turn off what does not apply to you, and add your own rules. ',
        d.canEdit ? 'A change moves the open findings at once where it can; risk scores and the rest follow when the accounts are analysed again, within a few minutes.' : 'You can read the policy; changing it needs the settings permission.')),
    h('div', { class: 'actions' }, h('a', { class: 'btn', href: `/api/controls.csv?q=${encodeURIComponent(S.q)}`, download: '' }, 'Export CSV'),
      d.canEdit && h('button', { class: 'btn primary', onClick: () => editor() }, 'Add custom control'))),
    tiles,
    h('section', { class: 'card' }, h('div', { class: 'filters' }, search, menus, count)),
    list, live);
}
