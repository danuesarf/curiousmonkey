// Configuration: Bedrock, and how far back CloudTrail history is read.
import { h, get, api, post, num, ago, fmtDay, toast } from '../lib.js';

const MODELS = [
  'global.anthropic.claude-sonnet-4-5-20250929-v1:0', 'apac.anthropic.claude-sonnet-4-5-20250929-v1:0', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
  'anthropic.claude-sonnet-4-5-20250929-v1:0', 'global.anthropic.claude-haiku-4-5-20251001-v1:0', 'apac.anthropic.claude-haiku-4-5-20251001-v1:0',
];
const LOOKBACKS = [90, 180, 365, 540, 730];
const sliceLabel = (v) => (v >= 1 ? `${v} h` : `${v * 60} min`);

export async function settingsPage(ctx) {
  const root = h('div', { class: 'stack-lg settings-page' });
  let d;
  async function load() { d = await get('/settings'); draw(); }

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
    const fmtVal = (k, v) => (k === 'history.sliceHours' ? sliceLabel(v) : /Days$/.test(k) ? `${v} days` : typeof v === 'boolean' ? (v ? 'on' : 'off') : String(v));
    const bind = (el, k, cast = (x) => x) => { el.addEventListener('input', () => { draft[k] = cast(el.type === 'checkbox' ? el.checked : el.value); refreshSave(); }); el.addEventListener('change', () => { draft[k] = cast(el.type === 'checkbox' ? el.checked : el.value); refreshSave(); }); return el; };
    const select = (k, opts, cast = Number) => { const s = h('select', null, opts.map(([v, l]) => h('option', { value: v }, l))); s.value = String(draft[k]); return bind(s, k, cast); };

    async function save(patch) {
      try {
        const r = await api('PUT', '/settings', patch);
        toast(r.changed.length ? 'Saved. The worker picks it up within 30 seconds.' : 'Nothing changed.');
        await load();
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
    const capped = d.history.filter((a) => a.cappedBy === 'workspace');

    const history = h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'How far back to read CloudTrail'), h('p', { class: 'muted small' }, 'Each account picks its own lookback. These limits apply to all of them.'))),
      h('div', { class: 'card-b settings-grid' },
        h('div', { class: 'stack' },
          h('div', { class: 'field' }, h('label', null, 'Maximum lookback (S3 trails)', maxSel),
            h('span', { class: 'hint' }, `No account reads further back than this. Event History stops at ${d.choices.eventHistoryMaxDays} days whatever is set here, because AWS keeps no more. Lowering it does not delete history already read.`), origin('history.maxLookbackDays')),
          h('div', { class: 'field' }, h('label', null, 'Default for new accounts', defSel),
            h('span', { class: 'hint' }, `Pre-selected when an account is added. Event History accounts get at most ${d.choices.eventHistoryMaxDays} days.`), origin('history.defaultLookbackDays')),
          h('div', { class: 'field' }, h('label', null, 'Slice size', sliceSel),
            h('span', { class: 'hint' }, 'History is read in slices of this length, each saved as it finishes. Smaller slices hold fewer events in memory, which helps busy accounts; larger ones mean fewer database round trips.'), origin('history.sliceHours')),
          saveBar(['history.maxLookbackDays', 'history.defaultLookbackDays', 'history.sliceHours'])),
        h('div', { class: 'stack' },
          capped.length > 0 && h('div', { class: 'alert warn' }, `${capped.length} account${capped.length > 1 ? 's ask' : ' asks'} for more than the maximum and ${capped.length > 1 ? 'are' : 'is'} read ${S['history.maxLookbackDays'].value} days back: ${capped.map((a) => a.name).join(', ')}.`),
          h('p', { class: 'small muted' }, 'Raising a limit makes the next scan backfill the extra days; history already read is kept and not read again.'))),
      historyTable(d.history));

    root.replaceChildren(
      h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'CONFIGURATION'), h('h1', null, 'Configuration'),
        h('p', { class: 'muted' }, `Settings saved here override the environment variables. Changes are recorded in the audit log.${d.awsMode === 'demo' ? ' Demo mode: AWS is not called.' : ''}`))),
      bedrock, history);
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
