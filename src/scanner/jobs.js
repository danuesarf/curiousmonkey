import { runInventory } from './inventory.js';
import { runEvents } from './events.js';
import { runAdvisor } from './advisor.js';
import { runAnalyze } from './analyzeJob.js';

export const handlers = { inventory: runInventory, events: runEvents, advisor: runAdvisor, analyze: runAnalyze };
