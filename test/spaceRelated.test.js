// Space: picking something keeps it and what is connected to it lit; everything else fades.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { related } from '../public/js/pages/spaceRelated.js';

// one account: two clusters, three roles, two services, an outside identity whose gate can enter one role,
// a neighbouring account chained into another, and the scanner reading a third
const cl1 = { id: 'cl:s3' }, cl2 = { id: 'cl:ecs' };
const roles = [{ id: 'api', cluster: cl1 }, { id: 'deploy', cluster: cl2 }, { id: 'batch', cluster: cl1 }];
const links = [
  { from: 'cl:s3', to: 'svc:s3', kind: 'use' }, { from: 'cl:ecs', to: 'svc:ecs', kind: 'use' },
  { from: 'api', to: 'svc:s3', kind: 'use1', owner: 'api' }, { from: 'deploy', to: 'svc:ecs', kind: 'use1', owner: 'deploy' }, { from: 'batch', to: 'svc:s3', kind: 'use1', owner: 'batch' },
  { from: 'src:idc', to: 'gate:idc', kind: 'extHigh' }, { from: 'gate:idc', to: 'deploy', kind: 'fan', src: 'src:idc' },
  { from: 'far:stg', to: 'api', kind: 'in' }, { from: 'cm', to: 'batch', kind: 'scan' },
].map((l, i) => ({ ...l, id: `link:${i}` }));
const M = { byRole: new Map(roles.map((r) => [r.id, r])), roles, links, gates: [{ id: 'gate:idc', src: 'src:idc', roles: ['deploy'] }] };
const lit = (sel) => [...related(M, sel)].filter((x) => !x.startsWith('link:')).sort();

test('a role lights its cluster, the services it calls, who can enter it and who it chains with; not the rest', () => {
  assert.deepEqual(lit('deploy'), ['cl:ecs', 'deploy', 'gate:idc', 'src:idc', 'svc:ecs']);
  assert.deepEqual(lit('api'), ['api', 'cl:s3', 'far:stg', 'svc:s3']);
  assert.ok(!related(M, 'api').has('batch'));                      // same cluster, but not connected to it
});

test('an outside identity lights its gate and every role it can enter; a service the roles that call it', () => {
  assert.deepEqual(lit('src:idc'), ['cl:ecs', 'deploy', 'gate:idc', 'src:idc']);   // and where those roles live
  assert.deepEqual(lit('svc:s3'), ['api', 'batch', 'cl:s3', 'svc:s3']);
  assert.deepEqual(lit('cm'), ['batch', 'cl:s3', 'cm']);
});

test('a path lights both its ends', () => {
  assert.deepEqual(lit('link:7'), ['api', 'cl:s3', 'far:stg']);
});

test('direction: In keeps who can get in, Out where it can go, and paths inside the account stay', async () => {
  const { dirFilter } = await import('../public/js/pages/spaceRelated.js');
  const acct = { view: 'account', links: [...links, { id: 'o', from: 'deploy', to: 'far:stg', kind: 'out' }] };
  const kinds = (dir) => acct.links.filter((l) => dirFilter(dir, acct, null).link(l)).map((l) => l.kind).sort();
  assert.deepEqual(kinds('in'), ['extHigh', 'fan', 'in', 'scan', 'use', 'use', 'use1', 'use1', 'use1']);
  assert.deepEqual(kinds('out'), ['out', 'use', 'use', 'use1', 'use1', 'use1']);
  assert.equal(kinds('both').length, acct.links.length);
  assert.equal(dirFilter('out', acct, null).inside, false);         // outside identities and the scanner only come in
  // the estate: relative to the account picked, nothing else
  const est = { view: 'estate', by: new Map([['prod', {}], ['stg', {}]]), links: [
    { id: 'a', from: 'src:gh', to: 'prod', kind: 'ext' }, { id: 'b', from: 'stg', to: 'prod', kind: 'chain' },
    { id: 'c', from: 'prod', to: 'stg', kind: 'chain' }, { id: 'd', from: 'src:gh', to: 'stg', kind: 'ext' }, { id: 'e', from: 'cm', to: 'prod', kind: 'scan' }] };
  const ids = (dir, sel) => est.links.filter((l) => dirFilter(dir, est, sel).link(l)).map((l) => l.id).join('');
  assert.equal(ids('in', 'prod'), 'abe');
  assert.equal(ids('out', 'prod'), 'c');
  assert.ok(dirFilter('in', est, 'prod').source('src:gh')); assert.ok(!dirFilter('in', est, 'prod').source('src:other'));
  // nothing picked: In is from outside the org, Out the paths between your accounts
  assert.equal(ids('in', null), 'ade'); assert.equal(ids('out', null), 'bc');
});

test('In and Out on the estate count who is at the other end, for every kind of path, in both clouds', async () => {
  const { wayEnds } = await import('../public/js/pages/spaceRelated.js');
  const M = { view: 'estate', by: new Map([['a', {}], ['b', {}], ['gcp:p', {}]]), links: [
    { id: '1', from: 'src:x', to: 'a', kind: 'extHigh' }, { id: '2', from: 'src:x', to: 'a', kind: 'resHigh' },   // one outsider, two paths
    { id: '3', from: 'src:y', to: 'a', kind: 'res' }, { id: '4', from: 'b', to: 'a', kind: 'chain' },
    { id: '5', from: 'cm', to: 'a', kind: 'scan' },                                                                 // the scanner: not counted
    { id: '6', from: 'a', to: 'gcp:p', kind: 'xcloud' }, { id: '7', from: 'b', to: 'gcp:p', kind: 'xcloudHigh' },
    { id: '8', from: 'gsrc:v', to: 'gcp:p', kind: 'extWarn' }, { id: '9', from: 'gcp:p', to: 'b', kind: 'xcloud' }] };
  assert.deepEqual([wayEnds(M, 'a', 'in'), wayEnds(M, 'a', 'out')], [3, 1]);
  assert.deepEqual([wayEnds(M, 'gcp:p', 'in'), wayEnds(M, 'gcp:p', 'out')], [3, 1]);
  assert.equal(wayEnds(M, null, 'in'), null);
});

test('In and Out in one account or project: outsiders by their paths to the gate (trust and resources), accounts at the edge', async () => {
  const { wayEnds } = await import('../public/js/pages/spaceRelated.js');
  const M = { view: 'account', links: [
    { id: '1', from: 'src:a', to: 'gate:a', kind: 'extHigh' }, { id: '2', from: 'src:a', to: 'gate:a', kind: 'resHigh' }, { id: '3', from: 'src:b', to: 'gate:b', kind: 'res' },
    { id: '4', from: 'gate:a', to: 'r1', kind: 'fan' }, { id: '5', from: 'far:x', to: 'r1', kind: 'in' }, { id: '6', from: 'r1', to: 'far:y', kind: 'out' }, { id: '7', from: 'cm', to: 'r1', kind: 'scan' }] };
  assert.deepEqual([wayEnds(M, null, 'in'), wayEnds(M, null, 'out')], [3, 1]);
});

test('the wheel: a pinch or a mouse wheel zooms, a two-finger swipe moves the view in any direction', async () => {
  const { wheelKind } = await import('../public/js/pages/spaceRelated.js');
  const k = (ev, mem = {}, now = 1000) => wheelKind({ deltaX: 0, deltaY: 0, deltaMode: 0, ...ev }, mem, now);
  assert.equal(k({ deltaY: 3.2, ctrlKey: true }), 'pinch');                       // trackpad pinch (the browser adds Ctrl)
  assert.equal(k({ deltaY: 12 }), 'pan');                                         // two fingers, up or down
  assert.equal(k({ deltaY: -7.5, deltaX: 2 }), 'pan');                             // two fingers, diagonal
  assert.equal(k({ deltaX: -20 }), 'pan');
  assert.equal(k({ deltaY: 100 }), 'zoom');                                        // a mouse notch (Chrome, Windows)
  assert.equal(k({ deltaY: 4, wheelDeltaY: -120 }), 'zoom');                       // a mouse notch on a Mac
  assert.equal(k({ deltaY: 3, deltaMode: 1 }), 'zoom');                            // Firefox: lines
  assert.equal(k({ deltaY: 3, metaKey: true }), 'zoom');
  assert.equal(k({ deltaY: 40, shiftKey: true }), 'pan');
  // a fast swipe whose step happens to look like a notch stays a swipe while the fingers move
  const mem = {};
  assert.equal(k({ deltaY: 20 }, mem, 1000), 'pan');
  assert.equal(k({ deltaY: 120 }, mem, 1050), 'pan');
  assert.equal(k({ deltaY: 120 }, mem, 1400), 'zoom');
});
