// SA-JS-05: Cryptographically secure random token generation
function generateSessionToken() {
  return crypto.randomUUID();
}
const buffer = new Uint8Array(32);
crypto.getRandomValues(buffer);
const csrfToken = Array.from(buffer, b => b.toString(16).padStart(2, '0')).join('');
