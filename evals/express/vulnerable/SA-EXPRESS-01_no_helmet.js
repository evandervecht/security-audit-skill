// SA-EXPRESS-01: Routes defined before helmet — no security headers
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
  res.json(users);
});

app.post('/api/users', (req, res) => {
  const user = createUser(req.body);
  res.json(user);
});

// Helmet added too late — routes above are unprotected
app.use(helmet());

app.listen(3000);
