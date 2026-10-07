// SA-NODE-03: safe code isolation via worker_threads with resource limits
const { Worker } = require('worker_threads');

function runUserCode(code) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('./sandbox-worker.js', {
      workerData: { code },
      resourceLimits: {
        maxOldGenerationSizeMb: 64,
        maxYoungGenerationSizeMb: 16,
        codeRangeSizeMb: 16,
      },
    });
    const timeout = setTimeout(() => {
      worker.terminate();
      reject(new Error('Execution timeout'));
    }, 5000);
    worker.on('message', (result) => {
      clearTimeout(timeout);
      resolve(result);
    });
    worker.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

module.exports = { runUserCode };
