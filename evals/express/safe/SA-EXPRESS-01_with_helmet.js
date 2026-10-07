// SA-EXPRESS-01: Safe — helmet registered before all routes
const express = require('express');
const helmetLib = require('helmet');
const app = express();

app.use(helmetLib());
app.use(express.json({ limit: '10kb' }));

app.get('/api/users', (req, res) => {
  res.json(users);
});

app.post('/api/users', (req, res) => {
  const user = createUser(req.body);
  res.json(user);
});

app.listen(3000);
