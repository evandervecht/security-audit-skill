// SA-NODE-05: dynamic require with user-controlled path
function loadPlugin(name) {
  const plugin = require(name + '/index');
  return plugin;
}

module.exports = { loadPlugin };
