const _ = require('lodash');
// merging with a static defaults object, or into a fresh object, is safe
_.merge(config, { timeout: 5000, retries: 3 });
Object.assign(target, { role: 'guest' });
const merged = _.merge({}, defaults);
