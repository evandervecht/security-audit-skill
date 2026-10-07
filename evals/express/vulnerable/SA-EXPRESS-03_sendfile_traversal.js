// SA-EXPRESS-03: Path traversal via res.sendFile with user input
const express = require('express');
const path = require('path');
const app = express();

app.get('/download', (req, res) => {
  res.sendFile(path.join(__dirname, 'uploads', req.query.file));
});
