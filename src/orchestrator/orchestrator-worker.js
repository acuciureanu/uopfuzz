import { parentPort, workerData } from 'worker_threads';
import { Orchestrator } from './index.js';

(async () => {
  try {
    const orchestrator = new Orchestrator(workerData.options);
    const results = await orchestrator.run();
    parentPort.postMessage({ type: 'success', results });
  } catch (error) {
    parentPort.postMessage({ type: 'error', error: error.message, stack: error.stack });
  }
})();
