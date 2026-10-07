const fs = require('fs');
const path = require('path');
// safe: resolve against a fixed base and verify containment before any fs call
const base = '/srv/uploads';
const full = path.resolve(base, path.basename(req.query.file));
if (full.startsWith(base)) {
  fs.createReadStream(full).pipe(res);
}
