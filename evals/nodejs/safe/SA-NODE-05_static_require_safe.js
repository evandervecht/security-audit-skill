// SA-NODE-05: safe plugin loading via allowlist
const ALLOWED_PLUGINS = {
  markdown: require('./plugins/markdown'),
  csv: require('./plugins/csv'),
  json: require('./plugins/json'),
};

function loadPlugin(name) {
  const plugin = ALLOWED_PLUGINS[name];
  if (!plugin) {
    throw new Error('Unknown plugin');
  }
  return plugin;
}

module.exports = { loadPlugin };
