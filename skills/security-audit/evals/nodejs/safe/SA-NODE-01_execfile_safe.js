// SA-NODE-01: safe command execution with execFile (no shell invocation)
const { execFile } = require('child_process');

function lookupHost(userInput, callback) {
  execFile('nslookup', [userInput], callback);
}

module.exports = { lookupHost };
