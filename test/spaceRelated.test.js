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
