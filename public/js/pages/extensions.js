// Admin → Extensions: optional features, each with what it adds and what the scanner has to read for it. Turning one
// on shows it in the menu and starts its reads; turning it off hides it and stops them (what it stored stays).
import { h, get, api, post, ago, toast, busy } from '../lib.js';
import { session, refreshShell } from '../main.js';

export async function extensionsPage() {
  const root = h('div', { class: 'stack-lg' });
  const may = session.user?.permissions.includes('settings');
  async function load() { draw((await get('/extensions')).items); }

  function draw(items) {
    root.replaceChildren(
      h('p', { class: 'small muted', style: 'max-width:760px' }, 'Extensions are optional features. Each one adds its own page and reads more from your accounts and projects, so it starts off. Turn one on and the next worker pass reads what it needs; turn it off and its page goes away and its reads stop. What it stored is kept until it is turned on again.'),
      ...items.map((x) => {
        const toggle = h('button', { class: `btn${x.enabled ? '' : ' primary'}`, disabled: !may, title: may ? null : 'Only owners and admins can turn extensions on or off.' }, x.enabled ? 'Turn off' : 'Turn on');
        toggle.addEventListener('click', () => busy(toggle, async () => {
          const r = await api('PUT', `/extensions/${x.key}`, { enabled: !x.enabled });
          session.extensions = r.items.filter((y) => y.enabled).map((y) => y.key);
          toast(`${x.name} ${x.enabled ? 'turned off' : 'turned on'}${!x.enabled && x.key === 'networking' ? ': the first read starts within a minute' : ''}`);
          refreshShell();
          draw(r.items);
        }));
        const readNow = x.enabled && x.key === 'networking' && h('button', { class: 'btn' }, 'Read now');
        if (readNow) readNow.addEventListener('click', () => busy(readNow, async () => { await post('/network/read'); toast('Networking will be read again within a minute'); }));
        return h('section', { class: 'card ext-card' },
          h('div', { class: 'card-h' },
            h('div', { class: 'stack', style: 'gap:2px' }, h('div', { class: 'row', style: 'gap:10px' }, h('b', { style: 'font-size:16px' }, x.name),
              h('span', { class: `badge ${x.enabled ? 'b-green' : 'b-neutral'}` }, x.enabled ? 'On' : 'Off')),
              h('span', { class: 'small muted' }, x.summary)),
            h('div', { class: 'row' }, x.enabled && x.key === 'networking' && h('a', { class: 'btn', href: '#/network' }, 'Open Networking'), readNow, toggle)),
          h('div', { class: 'ext-body' },
            h('div', null, h('div', { class: 'eyebrow' }, 'What it adds'), h('ul', { class: 'small' }, x.adds.map((a) => h('li', null, a)))),
            h('div', null, h('div', { class: 'eyebrow' }, 'What it reads'),
              h('p', { class: 'small' }, h('b', null, 'AWS: '), x.reads.aws),
              h('p', { class: 'small' }, h('b', null, 'Google Cloud: '), x.reads.gcp),
              h('p', { class: 'tiny muted' }, 'The scanner policy on Accounts → Add or Edit, and the Google Cloud setup commands, include these once the extension is on. A scanner role without them skips what it may not read and says so.'))),
          x.updatedAt && h('div', { class: 'card-f tiny muted' }, `${x.enabled ? 'Turned on' : 'Turned off'} ${ago(x.updatedAt)}${x.updatedBy ? ` by ${x.updatedBy}` : ''}`));
      }));
  }
  await load();
  return root;
}
