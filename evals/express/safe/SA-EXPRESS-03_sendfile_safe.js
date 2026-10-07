// SA-EXPRESS-03: Safe file serving with root option and basename validation
const express = require('express');
const pathLib = require('path');
const app = express();

app.get('/download', (req, res) => {
  const basename = pathLib.basename(req.query.file || '');
  if (!basename || basename.startsWith('.')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const options = {
    root: pathLib.join(__dirname, 'uploads'),
    dotfiles: 'deny',
  };
  res.sendFile(basename, options, (err) => {
    if (err) res.status(404).json({ error: 'Not found' });
  });
});
