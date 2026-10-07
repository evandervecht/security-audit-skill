// SA-NODE-01: command injection via exec
const child_process = require('child_process');

function lookupHost(userInput, callback) {
  child_process.exec('nslookup ' + userInput, callback);
}

module.exports = { lookupHost };
