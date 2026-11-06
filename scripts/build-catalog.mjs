// Builds src/analyzer/catalog.json from the @cloud-copilot/iam-data package (MIT).
// Re-run with `npm run catalog` to refresh the bundled AWS action list.
// Each action is encoded "<level><wildcardOnly><hasResourceTypes>", e.g. "R10".
//   level: R read, L list, W write, P permissions management, T tagging
import fs from 'node:fs';
import * as iam from '@cloud-copilot/iam-data';

const LEVEL = { Read: 'R', List: 'L', Write: 'W', 'Permissions management': 'P', Tagging: 'T' };
const out = { generatedAt: new Date().toISOString(), dataVersion: iam.iamDataVersion ? await iam.iamDataVersion() : null, services: {} };
let total = 0;
for (const svc of await iam.iamServiceKeys()) {
  const actions = {};
  for (const name of await iam.iamActionsForService(svc)) {
    const d = await iam.iamActionDetails(svc, name);
    const level = LEVEL[d.accessLevel] || 'W';
    actions[name] = `${level}${d.isWildcardOnly ? 1 : 0}${d.resourceTypes?.length ? 1 : 0}`;
    total++;
  }
  out.services[svc] = { n: await iam.iamServiceName(svc), a: actions };
}
fs.writeFileSync(new URL('../src/analyzer/catalog.json', import.meta.url), JSON.stringify(out));
console.log(`catalog: ${Object.keys(out.services).length} services, ${total} actions`);
