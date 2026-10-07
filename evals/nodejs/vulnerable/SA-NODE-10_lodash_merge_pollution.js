const _ = require('lodash');
// user-controlled deep merge - classic prototype pollution
_.merge(config, req.body);
_.defaultsDeep(settings, req.query);
Object.assign(target, req.body);
