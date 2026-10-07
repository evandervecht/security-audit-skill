// SA-NODE-02: safe file access with path validation
const path = require('path');
const { readFile } = require('fs/promises');

const UPLOAD_DIR = path.resolve('/app/uploads');

async function getFile(req, res) {
  const requested = path.resolve(UPLOAD_DIR, req.query.name);
  if (!requested.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(403).send('Forbidden');
  }
  try {
    const data = await readFile(requested);
    res.send(data);
  } catch {
    res.status(404).send('Not found');
  }
}

module.exports = { getFile };
