// Configuration: Bedrock, how far back CloudTrail history is read, and the environments accounts belong to.
import { h, get, api, post, num, ago, fmtDay, toast, copy, loadEnvironments, ROLE_LABEL, TEAM, tzName, setWorkspaceTimeZone } from '../lib.js';
import { session } from '../main.js';

const MODELS = [
  'global.anthropic.claude-sonnet-4-5-20250929-v1:0', 'apac.anthropic.claude-sonnet-4-5-20250929-v1:0', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
  'anthropic.claude-sonnet-4-5-20250929-v1:0', 'global.anthropic.claude-haiku-4-5-20251001-v1:0', 'apac.anthropic.claude-haiku-4-5-20251001-v1:0',
];
const LOOKBACKS = [90, 180, 365, 540, 730];
const sliceLabel = (v) => (v >= 1 ? `${v} h` : `${v * 60} min`);

const TAIL_CHOICES = [0, 1, 5, 10, 15, 30, 60, 120, 360];
const tailLabel = (v) => (!v ? 'Off (daily scan only)' : v < 60 ? `${v} min` : `${v / 60} h`);

export async function settingsPage(ctx) {
  const root = h('div', { class: 'stack-lg settings-page' });
  let d;
  async function load() {
    const owner = session.user?.role === 'owner';
    const [x, e, sso, maps] = await Promise.all([get('/settings'), get('/environments'), owner ? get('/settings/sso') : null, owner ? get('/sso/mappings') : null]);
    d = { ...x, environments: e.environments, sso, ssoMappings: maps?.items || [] }; draw();
  }

  function draw() {
    const S = d.settings;
    const draft = Object.fromEntries(Object.entries(S).map(([k, v]) => [k, v.value]));
    const dirty = () => Object.keys(draft).filter((k) => JSON.stringify(draft[k]) !== JSON.stringify(S[k].value));
    const saveBtns = [];
    const refreshSave = () => saveBtns.forEach(([b, keys]) => { const n = dirty().filter((k) => keys.includes(k)).length; b.disabled = !n; b.textContent = n ? `Save ${n} change${n > 1 ? 's' : ''}` : 'Saved'; });

    // one setting: control, where its value comes from, and a reset to the default
    const origin = (k) => h('span', { class: 'hint' }, S[k].overridden
      ? h('span', null, `Changed here ${ago(S[k].updatedAt)}. Default ${fmtVal(k, S[k].default)}${S[k].env ? ` (${S[k].env})` : ''}. `,
        h('a', { href: '#', onClick: async (e) => { e.preventDefault(); await save({ [k]: null }); } }, 'Reset to default'))
      : `Default${S[k].env ? `, from ${S[k].env} or built in` : ''}.`);
    const fmtVal = (k, v) => (k === 'history.tailEveryMinutes' ? tailLabel(v) : k === 'history.sliceHours' ? sliceLabel(v) : /Days$/.test(k) ? `${v} days` : typeof v === 'boolean' ? (v ? 'on' : 'off') : String(v));
    const bind = (el, k, cast = (x) => x) => { el.addEventListener('input', () => { draft[k] = cast(el.type === 'checkbox' ? el.checked : el.value); refreshSave(); }); el.addEventListener('change', () => { draft[k] = cast(el.type === 'checkbox' ? el.checked : el.value); refreshSave(); }); return el; };
    const select = (k, opts, cast = Number) => { const s = h('select', null, opts.map(([v, l]) => h('option', { value: v }, l))); s.value = String(draft[k]); return bind(s, k, cast); };

    async function save(patch) {
      try {
        const r = await api('PUT', '/settings', patch);
        toast(r.changed.length ? 'Saved. The worker picks it up within 30 seconds.' : 'Nothing changed.');
        await load();
        setWorkspaceTimeZone(d.settings['display.timeZone']?.value);      // this browser follows a new workspace zone at once
      } catch (e) { toast(e.message, true); }
    }
    const saveBar = (keys) => {
      const b = h('button', { class: 'btn primary', onClick: () => save(Object.fromEntries(dirty().filter((k) => keys.includes(k)).map((k) => [k, draft[k]]))) }, 'Saved');
      saveBtns.push([b, keys]); return h('div', { class: 'actions' }, b);
    };

    // ---- Bedrock ----
    const on = bind(h('input', { type: 'checkbox' }), 'ai.enabled'); on.checked = draft['ai.enabled'];
    const region = bind(h('input', { value: draft['ai.region'], placeholder: 'ap-southeast-1', class: 'mono', spellcheck: 'false' }), 'ai.region');
    const model = bind(h('input', { value: draft['ai.modelId'], list: 'bedrock-models', class: 'mono', spellcheck: 'false' }), 'ai.modelId');
    const tokens = bind(h('input', { type: 'number', min: 1000, max: 64000, step: 500, value: draft['ai.maxTokens'] }), 'ai.maxTokens', Number);
    const result = h('div', { class: 'test-result' });
    const testBtn = h('button', { class: 'btn', onClick: async () => {
      testBtn.disabled = true; result.replaceChildren(h('span', { class: 'spin' }), ' Calling Bedrock…');
      try {
        const r = await post('/settings/bedrock/test', { region: draft['ai.region'], modelId: draft['ai.modelId'] });
        result.replaceChildren(r.ok
          ? h('div', { class: 'alert ok' }, h('b', null, 'Bedrock answered. '), `${r.modelId} in ${r.region} replied “${r.reply}” in ${num(r.latencyMs)} ms`, r.inputTokens != null ? ` (${r.inputTokens} in, ${r.outputTokens} out tokens).` : '.')
          : h('div', { class: 'alert bad' }, h('b', null, 'The call failed. '), h('span', { class: 'mono small' }, r.error), r.hint && h('div', null, r.hint)));
      } catch (e) { result.replaceChildren(h('div', { class: 'alert bad' }, e.message)); }
      testBtn.disabled = false;
    } }, 'Test connection');
    const use = d.ai.recommendations;
    const aiDrafts = use.filter((x) => x.source === 'ai').reduce((n, x) => n + x.n, 0);
    const fallbacks = use.filter((x) => x.source === 'rules-fallback').reduce((n, x) => n + x.n, 0);

    const bedrock = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Bedrock'), h('p', { class: 'muted small' }, 'Used to draft least-privilege policies and to suggest mappings for unidentified event names. Every draft is still checked by the rules; the model only proposes.')),
        h('span', { class: `badge ${S['ai.enabled'].value ? 'b-green' : 'b-neutral'}` }, S['ai.enabled'].value ? 'On' : 'Off')),
      h('div', { class: 'card-b settings-grid' },
        h('div', { class: 'stack' },
          h('div', { class: 'field' }, h('label', { class: 'check' }, on, h('span', null, 'Use Bedrock')), h('span', { class: 'hint' }, 'When off, drafts come from the rules alone and the Suggest button on unidentified calls is hidden.'), origin('ai.enabled')),
          h('div', { class: 'field' }, h('label', null, 'Region', region), origin('ai.region')),
          h('div', { class: 'field' }, h('label', null, 'Model or inference profile ID', model),
            h('datalist', { id: 'bedrock-models' }, MODELS.map((m) => h('option', { value: m }))),
            h('span', { class: 'hint' }, 'Newer Claude models need an inference profile: put apac., us. or global. in front of the model ID. The identity calling Bedrock needs bedrock:InvokeModel on the model and on the profile.'), origin('ai.modelId')),
          h('div', { class: 'field' }, h('label', null, 'Max output tokens per call', tokens), origin('ai.maxTokens')),
          h('div', { class: 'row' }, testBtn, h('span', { class: 'small muted' }, 'Sends one short prompt with the values above, saved or not.')),
          result,
          saveBar(['ai.enabled', 'ai.region', 'ai.modelId', 'ai.maxTokens'])),
        h('div', { class: 'stack' },
          h('div', { class: 'tiles' },
            h('div', { class: 'tile' }, h('span', { class: 'small muted' }, 'AI drafts, 30 days'), h('b', null, num(aiDrafts))),
            h('div', { class: 'tile' }, h('span', { class: 'small muted' }, 'Fell back to rules'), h('b', null, num(fallbacks))),
            h('div', { class: 'tile' }, h('span', { class: 'small muted' }, 'Mapping suggestions'), h('b', null, num(d.ai.mappingSuggestions?.n || 0)))),
          use.length ? h('table', { class: 'small' }, h('thead', null, h('tr', null, ['Draft source', 'Model', 'Drafts', 'Last'].map((x) => h('th', null, x)))),
            h('tbody', null, use.map((x) => h('tr', null, h('td', null, x.source), h('td', { class: 'mono tiny' }, x.model || '—'), h('td', null, num(x.n)), h('td', null, ago(x.last))))))
            : h('p', { class: 'muted small' }, 'No drafts in the last 30 days.'),
          fallbacks > 0 && h('p', { class: 'small muted' }, '“Fell back to rules” means Bedrock was asked but its draft failed the checks or the call failed, so the rules draft was used.'))));

    // ---- History ----
    const maxSel = select('history.maxLookbackDays', [...new Set([...LOOKBACKS, draft['history.maxLookbackDays']])].sort((a, b) => a - b).map((v) => [v, `${v} days`]));
    const defSel = select('history.defaultLookbackDays', [...new Set([30, 60, 90, ...LOOKBACKS, draft['history.defaultLookbackDays']])].sort((a, b) => a - b).map((v) => [v, `${v} days`]));
    const sliceSel = select('history.sliceHours', d.choices.sliceHours.map((v) => [v, sliceLabel(v)]));
    const tailSel = select('history.tailEveryMinutes', [...new Set([...TAIL_CHOICES, draft['history.tailEveryMinutes']])].sort((a, b) => a - b).map((v) => [v, tailLabel(v)]));
    const capped = d.history.filter((a) => a.cappedBy === 'workspace');

    const history = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'How far back to read CloudTrail'), h('p', { class: 'muted small' }, 'Each account picks its own lookback. These limits apply to all of them.'))),
      h('div', { class: 'card-b settings-grid' },
        h('div', { class: 'stack' },
          h('div', { class: 'field' }, h('label', null, 'Maximum lookback (S3 trails)', maxSel),
            h('span', { class: 'hint' }, `No account reads further back than this. Event History stops at ${d.choices.eventHistoryMaxDays} days whatever is set here, because AWS keeps no more. Lowering it does not delete history already read.`), origin('history.maxLookbackDays')),
          h('div', { class: 'field' }, h('label', null, 'Default for new accounts', defSel),
            h('span', { class: 'hint' }, `Pre-selected when an account is added. Event History accounts get at most ${d.choices.eventHistoryMaxDays} days.`), origin('history.defaultLookbackDays')),
          h('div', { class: 'field' }, h('label', null, 'Slice size (Event History)', sliceSel),
            h('span', { class: 'hint' }, 'Event History accounts only: their history is read in slices of this length, each saved as it finishes. S3 trails are read file by file and need no slice size.'), origin('history.sliceHours')),
          h('div', { class: 'field' }, h('label', null, 'Read new events every', tailSel),
            h('span', { class: 'hint' }, 'Between daily scans, each account whose history is complete has the CloudTrail events that arrived since its last read read in, and results refreshed. Roles, policies and Access Advisor still update once a day. CloudTrail delivers events about 5 to 15 minutes late, so an interval below that only adds AWS calls. Off: new events wait for the daily scan.'), origin('history.tailEveryMinutes')),
          saveBar(['history.maxLookbackDays', 'history.defaultLookbackDays', 'history.sliceHours', 'history.tailEveryMinutes'])),
        h('div', { class: 'stack' },
          capped.length > 0 && h('div', { class: 'alert warn' }, `${capped.length} account${capped.length > 1 ? 's ask' : ' asks'} for more than the maximum and ${capped.length > 1 ? 'are' : 'is'} read ${S['history.maxLookbackDays'].value} days back: ${capped.map((a) => a.name).join(', ')}.`),
          h('p', { class: 'small muted' }, 'Raising a limit makes the next scan backfill the extra days; history already read is kept and not read again.'))),
      historyTable(d.history));

    // ---- time zone ----
    const zones = (() => { try { return Intl.supportedValuesOf('timeZone'); } catch { return []; } })();
    const tzInput = bind(h('input', { value: draft['display.timeZone'], list: 'tz-list', class: 'mono', spellcheck: 'false', autocomplete: 'off' }), 'display.timeZone', (v) => v.trim());
    const tzNow = h('span', { class: 'hint' });
    const showNow = () => { try { tzNow.textContent = `Now there: ${new Date().toLocaleString('en-GB', { timeZone: draft['display.timeZone'], hour: '2-digit', minute: '2-digit', weekday: 'short' })} ${tzName(draft['display.timeZone'])}.`; } catch { tzNow.textContent = 'Not a time zone this browser knows.'; } };
    tzInput.addEventListener('input', showNow); showNow();
    const clock = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Time zone'), h('p', { class: 'muted small' }, 'The zone times are shown in for everyone. Each person can switch to their own browser’s zone from their menu (the avatar at the bottom of the rail).'))),
      h('div', { class: 'card-b settings-grid' },
        h('div', { class: 'stack' },
          h('div', { class: 'field' }, h('label', null, 'Show times in', tzInput), h('datalist', { id: 'tz-list' }, zones.map((z) => h('option', { value: z }))), tzNow,
            h('span', { class: 'hint' }, 'An IANA zone, such as Asia/Jakarta, Asia/Singapore or Europe/London.'), origin('display.timeZone')),
          saveBar(['display.timeZone'])),
        h('div', { class: 'stack' }, h('p', { class: 'small muted' }, `The daily scan and alert digests run on the server’s schedule zone (${d.scheduleTz || 'SCAN_TZ'}), which this does not change.`))));

    // ---- risk thresholds ----
    const rotate = bind(h('input', { type: 'number', min: 7, max: 730, step: 1, value: draft['risk.keyRotateDays'] }), 'risk.keyRotateDays', Number);
    const unused = bind(h('input', { type: 'number', min: 7, max: 730, step: 1, value: draft['risk.keyUnusedDays'] }), 'risk.keyUnusedDays', Number);
    const risk = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Risk thresholds'), h('p', { class: 'muted small' }, 'When an IAM user\'s credentials count against it. Used by the analysis, the IAM users list and alerts.'))),
      h('div', { class: 'card-b settings-grid' },
        h('div', { class: 'stack' },
          h('div', { class: 'field' }, h('label', null, 'Rotate access keys after (days)', rotate),
            h('span', { class: 'hint' }, 'An active key older than this is flagged "rotate it" (Google Cloud service account keys too). Many policies ask for 90.'), origin('risk.keyRotateDays')),
          h('div', { class: 'field' }, h('label', null, 'Unused after (days)', unused),
            h('span', { class: 'hint' }, 'A key or console password not used for this long is flagged for removal, and a user with no activity this long counts as inactive.'), origin('risk.keyUnusedDays')),
          saveBar(['risk.keyRotateDays', 'risk.keyUnusedDays'])),
        h('div', { class: 'stack' }, h('p', { class: 'small muted' }, 'The IAM users list follows a change at once. Risk levels and findings follow at each identity\'s next analysis: the next catch-up read, or the daily scan.'),
          h('p', { class: 'small muted' }, h('a', { href: '#/admin/alerts' }, 'Alerts'), ' can post when a key passes the rotation age.'))));

    root.replaceChildren(
      h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'CONFIGURATION'), h('h1', null, 'Configuration'),
        h('p', { class: 'muted' }, `Settings saved here override the environment variables. Changes are recorded in the audit log.${d.awsMode === 'demo' ? ' Demo mode: AWS is not called.' : ''}`))),
      d.sso && ssoCard(d.sso, d.ssoMappings, load), bedrock, history, risk, clock, environmentsCard(d.environments, load));
    refreshSave();
  }

  load().catch((e) => root.replaceChildren(h('div', { class: 'alert bad' }, e.message)));
  return root;
}

// One row per account and region: how far back it is read, against what it should be.
function historyTable(rows) {
  if (!rows.length) return h('div', { class: 'empty' }, 'No accounts yet.');
  const bar = (r, eff) => {
    const b = h('div', { class: 'reach-bar', role: 'img', 'aria-label': `${r.daysRead} of ${eff} days read` });
    const i = h('i', { class: r.complete ? 'done' : '' }); i.style.width = `${Math.min(100, (r.daysRead / Math.max(eff, 1)) * 100)}%`; b.append(i);
    return b;
  };
  return h('div', { class: 'scroll' }, h('table', { class: 'small reach-table' },
    h('thead', null, h('tr', null, ['Account', 'Source', 'Lookback', 'Region', 'Read back to', 'Coverage', 'Events'].map((x) => h('th', null, x)))),
    h('tbody', null, rows.flatMap((a) => a.regions.map((r, i) => row(a, r, i, bar))))));
}
function row(a, r, i, bar) {
  const cells = [];
  if (i === 0) {
    cells.push(h('td', { rowspan: a.regions.length }, h('a', { href: `#/accounts/${a.id}/edit`, class: 'name' }, a.name), h('div', { class: 'tiny muted mono' }, a.accountId)));
    cells.push(h('td', { rowspan: a.regions.length }, a.source === 's3' ? 'S3 trail' : 'Event History'));
    cells.push(h('td', { rowspan: a.regions.length }, `${a.effectiveDays} days`,
      a.cappedBy && h('div', { class: 'tiny muted' }, `asks ${a.lookbackDays}, capped by ${a.cappedBy === 'workspace' ? 'the maximum' : 'Event History'}`)));
  }
  cells.push(h('td', { class: 'mono' }, r.region),
    h('td', null, r.backTo ? fmtDay(r.backTo) : h('span', { class: 'muted' }, 'not read yet'), r.gap && h('div', { class: 'tiny err' }, 'gap: the worker was down longer than the history lasts')),
    h('td', null, h('div', { class: 'row nowrap' }, bar(r, a.effectiveDays), h('span', { class: 'tiny muted' }, r.complete ? 'complete' : `${r.daysRead} of ${a.effectiveDays} days`))),
    h('td', null, num(r.events)));
  return h('tr', { class: i === a.regions.length - 1 ? 'group-end' : '' }, ...cells);
}

// Environments: add, rename, recolour, reorder, remove. Removing one that accounts use asks where they go.
const SWATCHES = ['#c68405', '#676815', '#4b95f0', '#37ac78', '#a947a3', '#e0614f', '#2fb5c4', '#8f7cf0', '#d0a43a', '#7e978a'];
function environmentsCard(saved, reload) {
  let rows = saved.map((e) => ({ ...e }));
  const reassign = {};
  const box = h('div', { class: 'card-b stack' });
  const removed = () => saved.filter((e) => !rows.some((r) => r.id === e.id));
  const changed = () => JSON.stringify(rows.map(({ id, name, color }) => [id, name, color])) !== JSON.stringify(saved.map(({ id, name, color }) => [id, name, color]));
  const draw = () => {
    const err = h('div', { class: 'err', role: 'alert' });
    const line = (r, i) => {
      const color = h('input', { type: 'color', value: r.color, 'aria-label': `Colour of ${r.name || 'new environment'}`, class: 'env-color' });
      color.addEventListener('input', () => { r.color = color.value; save.disabled = !changed(); });
      const name = h('input', { value: r.name, maxlength: '40', 'aria-label': 'Name', placeholder: 'Name, e.g. Non-production' });
      name.addEventListener('input', () => { r.name = name.value; save.disabled = !changed(); });
      const move = (d) => { const j = i + d; [rows[i], rows[j]] = [rows[j], rows[i]]; draw(); };
      return h('div', { class: 'env-row' }, color, name,
        h('span', { class: 'tiny muted mono env-meta' }, r.id ? `${r.id} · ${r.accounts || 0} account${r.accounts === 1 ? '' : 's'}` : 'new'),
        h('div', { class: 'row', style: 'gap:4px' },
          h('button', { class: 'btn sm', type: 'button', title: 'Earlier (further east in Space)', disabled: i === 0, onClick: () => move(-1) }, '↑'),
          h('button', { class: 'btn sm', type: 'button', title: 'Later', disabled: i === rows.length - 1, onClick: () => move(1) }, '↓'),
          h('button', { class: 'btn sm', type: 'button', title: 'Remove', disabled: rows.length === 1, onClick: () => { rows.splice(i, 1); draw(); } }, 'Remove')));
    };
    // where the accounts of a removed environment go
    const moves = removed().filter((e) => e.accounts).map((e) => {
      const keep = rows.filter((r) => r.id);
      if (!keep.some((r) => r.id === reassign[e.id])) reassign[e.id] = keep[0]?.id;
      const sel = h('select', { 'aria-label': `Move the accounts in ${e.name} to` }, keep.map((r) => h('option', { value: r.id, selected: r.id === reassign[e.id] }, r.name)));
      sel.addEventListener('change', () => { reassign[e.id] = sel.value; });
      return h('div', { class: 'alert warn row', style: 'gap:8px;flex-wrap:wrap' }, `Removing ${e.name}: move its ${e.accounts} account${e.accounts === 1 ? '' : 's'} to`, sel);
    });
    const add = h('button', { class: 'btn sm', type: 'button', disabled: rows.length >= 12, onClick: () => {
      rows.push({ name: '', color: SWATCHES.find((c) => !rows.some((r) => r.color === c)) || SWATCHES[0], accounts: 0 }); draw(); box.querySelector('.env-row:last-of-type input:not([type=color])')?.focus(); } }, 'Add environment');
    const save = h('button', { class: 'btn primary', type: 'button', disabled: !changed(), onClick: async () => {
      save.disabled = true;
      try {
        const r = await api('PUT', '/environments', { environments: rows.map(({ id, name, color }) => ({ ...(id ? { id } : {}), name, color })), reassign });
        await loadEnvironments(true);
        const moved = Object.values(r.moved || {}).reduce((n, x) => n + x.accounts, 0);
        toast(`Environments saved${moved ? `; ${moved} account${moved === 1 ? '' : 's'} moved` : ''}.`);
        await reload();
      } catch (e) { err.textContent = e.message; save.disabled = false; }
    } }, 'Save environments');
    const reset = h('button', { class: 'btn sm', type: 'button', disabled: !changed(), onClick: () => { rows = saved.map((e) => ({ ...e })); draw(); } }, 'Undo changes');
    box.replaceChildren(h('div', { class: 'env-list stack' }, ...rows.map(line)), ...moves, err, h('div', { class: 'row' }, add, h('span', { class: 'spacer' }), reset, save));
    if (moves.length || rows.some((r) => !r.id)) save.disabled = false;
  };
  draw();
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Environments'),
      h('p', { class: 'muted small' }, 'What an account can be: the zones in Space, the groups on Radar and the Trust map, the filters on Roles. The order is east to west in Space. Renaming keeps every account where it is.'))),
    box);
}

// Single sign-on (owners only). JumpCloud fixes the issuer, scopes and claim name, so the preset fills them and the
// owner pastes the client ID and secret. Signing in with a password keeps working, as the way back in if SSO breaks.
const JC_STEPS = [
  'In the JumpCloud admin portal: SSO Applications → Add New Application → Custom OIDC App. Name it Curious Monkey.',
  'On the SSO tab, paste the Redirect URI and Login URL below. Client authentication type: Client Secret Basic.',
  'Attribute mapping: tick the Email and Profile standard scopes. Turn on Include group attribute and name it groups.',
  'On the User Groups tab, tick the groups that should get in. Activate, then copy the client ID and secret here (JumpCloud shows the secret once).',
  'Map those group names to roles under Group mappings, below. Someone in no mapped group is turned away.',
];
function ssoCard(v, mappings, reload) {
  const P = v.presets;
  const st = { provider: v.provider, enabled: v.source === 'none' ? true : v.enabled };
  const regionOf = (iss) => Object.entries(P.jumpcloud.issuers).find(([, u]) => u === iss)?.[0] || 'us';
  const err = h('div', { class: 'err', role: 'alert' });
  const result = h('div', { class: 'test-result' });
  const provider = h('select', null, Object.entries(P).map(([k, p]) => h('option', { value: k, selected: k === v.provider }, p.label)));
  const region = h('select', null, [['us', 'US (default)'], ['eu', 'EU'], ['in', 'India']].map(([k, l]) => h('option', { value: k, selected: k === regionOf(v.issuer) }, l)));
  const issuer = h('input', { value: v.issuer || P[v.provider].issuers.us || '', class: 'mono', spellcheck: 'false', placeholder: 'https://idp.example.com/' });
  const clientId = h('input', { value: v.clientId || '', class: 'mono', spellcheck: 'false', autocomplete: 'off' });
  const secret = h('input', { type: 'password', autocomplete: 'new-password', placeholder: v.hasSecret ? 'Saved. Leave empty to keep it.' : 'Paste the client secret' });
  const groups = h('input', { value: v.groupsClaim || P[v.provider].groupsClaim, class: 'mono', spellcheck: 'false' });
  const scopes = h('input', { value: v.source === 'none' ? P[v.provider].scopes : v.scopes, class: 'mono', spellcheck: 'false' });
  const label = h('input', { value: v.buttonLabel || (v.provider === 'jumpcloud' ? 'JumpCloud' : ''), maxlength: '60', placeholder: 'company SSO' });
  const on = h('input', { type: 'checkbox', checked: st.enabled });
  const regionField = h('div', { class: 'field' }, h('label', null, 'JumpCloud region', region), h('span', { class: 'hint' }, 'Where your JumpCloud organisation lives. Sets the issuer.'));
  const steps = h('details', { class: 'sso-steps', open: v.source === 'none' }, h('summary', null, 'Set up the app in JumpCloud'), h('ol', { class: 'small' }, JC_STEPS.map((t) => h('li', null, t))));
  const sync = () => {
    const jc = provider.value === 'jumpcloud';
    regionField.hidden = !jc; steps.hidden = !jc;
    issuer.readOnly = jc;
    if (jc) issuer.value = P.jumpcloud.issuers[region.value];
  };
  provider.addEventListener('change', () => {
    const p = P[provider.value];
    scopes.value = p.scopes; groups.value = p.groupsClaim;
    if (provider.value === 'jumpcloud' && !label.value) label.value = 'JumpCloud';
    if (provider.value !== 'jumpcloud' && issuer.readOnly) issuer.value = '';
    sync();
  });
  region.addEventListener('change', sync);
  sync();

  const copyRow = (name, value) => h('div', { class: 'field' }, h('label', null, name),
    h('div', { class: 'row', style: 'gap:6px' }, h('input', { readonly: true, value, class: 'mono', onFocus: (e) => e.target.select() }), h('button', { class: 'btn sm', type: 'button', onClick: () => copy(value) }, 'Copy')));

  const test = h('button', { class: 'btn', type: 'button', onClick: async () => {
    test.disabled = true; result.replaceChildren(h('span', { class: 'spin' }), ' Reading the provider’s discovery document…');
    try {
      const r = await post('/settings/sso/test', { issuer: issuer.value, groupsClaim: groups.value });
      result.replaceChildren(r.ok
        ? h('div', { class: `alert ${r.notes.length ? 'warn' : 'ok'}` }, h('b', null, 'The provider answered. '), `Issuer ${r.issuer}.`, ...r.notes.map((n) => h('div', null, n)))
        : h('div', { class: 'alert bad' }, h('b', null, 'Could not reach the provider. '), r.message));
    } catch (e) { result.replaceChildren(h('div', { class: 'alert bad' }, e.message)); }
    test.disabled = false;
  } }, 'Check issuer');

  const save = h('button', { class: 'btn primary', type: 'submit' }, 'Save single sign-on');
  const form = h('form', { class: 'stack', onSubmit: async (e) => {
    e.preventDefault(); err.textContent = ''; save.disabled = true;
    try {
      await api('PUT', '/settings/sso', { enabled: on.checked, provider: provider.value, issuer: issuer.value, clientId: clientId.value, clientSecret: secret.value || undefined,
        groupsClaim: groups.value, scopes: scopes.value, buttonLabel: label.value || undefined });
      toast(on.checked ? 'Single sign-on saved. The sign-in page now shows its button.' : 'Saved. Single sign-on is off.');
      await reload();
    } catch (x) { err.textContent = x.message; save.disabled = false; }
  } },
    h('div', { class: 'field' }, h('label', { class: 'check' }, on, h('span', null, 'Offer single sign-on on the sign-in page')),
      h('span', { class: 'hint' }, 'Password sign-in keeps working, so an owner can still get in if the provider is down or misconfigured.')),
    h('div', { class: 'field' }, h('label', null, 'Identity provider', provider)), regionField,
    h('div', { class: 'field' }, h('label', null, 'Issuer', issuer), h('span', { class: 'hint' }, 'Must match the provider exactly, trailing slash included.')),
    h('div', { class: 'field' }, h('label', null, 'Client ID', clientId)),
    h('div', { class: 'field' }, h('label', null, 'Client secret', secret), h('span', { class: 'hint' }, 'Stored encrypted. It is never shown again, here or in the audit log.')),
    h('div', { class: 'field' }, h('label', null, 'Groups claim', groups), h('span', { class: 'hint' }, 'The name of the claim that lists the user’s groups. For JumpCloud: the name you gave the group attribute.')),
    h('details', null, h('summary', { class: 'small' }, 'More'),
      h('div', { class: 'stack', style: 'margin-top:10px' },
        h('div', { class: 'field' }, h('label', null, 'Scopes', scopes), h('span', { class: 'hint' }, 'JumpCloud: openid email profile. Groups come from the group attribute, not a scope.')),
        h('div', { class: 'field' }, h('label', null, 'Button text', label), h('span', { class: 'hint' }, 'Shown as “Sign in with …”.')))),
    err,
    h('div', { class: 'row' }, test, h('span', { class: 'spacer' }),
      v.source === 'saved' && h('button', { class: 'btn', type: 'button', title: v.envSet ? 'Use the OIDC_* environment variables again' : 'Turn single sign-on off and forget these values', onClick: async () => {
        if (!confirm(v.envSet ? 'Forget these values and use the OIDC_* environment variables again?' : 'Forget these values? Single sign-on turns off.')) return;
        await api('DELETE', '/settings/sso'); toast('Removed.'); await reload();
      } }, v.envSet ? 'Use environment instead' : 'Remove'),
      save),
    result);

  const badge = v.enabled ? (v.source === 'env' ? ['b-neutral', 'On (environment)'] : ['b-green', 'On']) : ['b-neutral', 'Off'];
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Single sign-on'),
      h('p', { class: 'muted small' }, 'Let people sign in with your identity provider (OIDC). Their groups decide their role. Only owners see this.')),
      h('span', { class: `badge ${badge[0]}` }, badge[1])),
    h('div', { class: 'card-b settings-grid' },
      form,
      h('div', { class: 'stack' },
        h('p', { class: 'small muted' }, 'Give your identity provider these two addresses:'),
        copyRow('Redirect URI', v.redirectUri), copyRow('Login URL', v.loginUrl),
        steps,
        h('div', { class: `alert ${mappings.length ? 'ok' : 'warn'}` },
          mappings.length ? `${mappings.length} group${mappings.length === 1 ? '' : 's'} mapped to roles: ${mappings.map((m) => m.group_name).join(', ')}. ` : 'No groups are mapped to roles yet, so nobody can get in with SSO. ',
          'Map them below.'),
        v.source === 'env' && h('p', { class: 'small muted' }, 'Now set by the OIDC_* environment variables. Saving here overrides them.'),
        v.updatedAt && h('p', { class: 'small muted' }, `Changed here ${ago(v.updatedAt)}.`))),
    mappingsBlock(mappings, reload));
}

// Which identity-provider group gets which role (and review team). Owners only, like the card around it.
function mappingsBlock(items, reload) {
  const group = h('input', { placeholder: 'IdP group name', 'aria-label': 'IdP group name' }), role = h('select', { 'aria-label': 'Role' }, Object.keys(ROLE_LABEL).map((r) => h('option', { value: r }, ROLE_LABEL[r])));
  const team = h('select', { 'aria-label': 'Review team' }, [['', 'No team'], ...Object.entries(TEAM)].map(([v, l]) => h('option', { value: v }, l)));
  return h('div', { class: 'card-b stack' }, h('h3', null, 'Group mappings'), h('p', { class: 'small muted' }, 'OIDC sign-in maps IdP groups to roles. This path has not been tested against a live identity provider.'),
    items.length ? h('ul', { class: 'plain' }, items.map((s) => h('li', { class: 'row' }, h('code', null, s.group_name), '→', ROLE_LABEL[s.role], s.team && `, ${TEAM[s.team]}`,
      h('button', { class: 'btn sm', onClick: async () => { await api('DELETE', `/sso/mappings/${encodeURIComponent(s.group_name)}`); reload(); } }, 'Remove')))) : h('p', { class: 'muted' }, 'No mappings yet.'),
    h('form', { class: 'row', onSubmit: async (e) => { e.preventDefault(); try { await api('PUT', '/sso/mappings', { group_name: group.value, role: role.value, team: team.value || null }); reload(); } catch (x) { toast(x.message, true); } } },
      group, role, team, h('button', { class: 'btn', type: 'submit' }, 'Add mapping')));
}
