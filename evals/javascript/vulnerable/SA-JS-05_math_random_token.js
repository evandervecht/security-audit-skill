// SA-JS-05: Math.random() for security token generation
function generateSessionToken() {
  return Math.random().toString(36).substring(2);
}
const csrfToken = Math.random().toString(16).slice(2);
