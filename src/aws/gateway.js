import { config } from '../config.js';
import { realGateway } from './real.js';
import { demoGateway } from '../demo/gateway.js';

/** One interface, two implementations. `AWS_MODE=demo` never touches AWS. */
export async function getGateway(account, workspace) {
  if (config.awsMode === 'demo') return demoGateway(account);
  return realGateway(account, { externalId: workspace.external_id });
}
