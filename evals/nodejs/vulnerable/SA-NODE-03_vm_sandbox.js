// SA-NODE-03: vm module used as security sandbox (it is NOT a security boundary)
const vm = require('vm');

function runUserCode(code) {
  const sandbox = { result: null };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  return sandbox.result;
}

module.exports = { runUserCode };
