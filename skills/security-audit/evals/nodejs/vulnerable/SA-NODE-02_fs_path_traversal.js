// SA-NODE-02: path traversal via fs.readFile with user input
const fs = require('fs');

function getFile(req, res) {
  fs.readFile('/app/uploads/' + req.query.name, (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
}

module.exports = { getFile };
