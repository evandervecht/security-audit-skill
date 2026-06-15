const fs = require('fs');
// path traversal via fs sinks the old 4-verb pattern missed
fs.createReadStream(req.query.file).pipe(res);
fs.appendFile(req.body.path, data, cb);
fs.rm(req.params.target, cb);
