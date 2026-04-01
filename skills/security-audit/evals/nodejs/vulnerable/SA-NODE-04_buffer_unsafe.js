// SA-NODE-04: Buffer.allocUnsafe leaks uninitialized memory
function createResponse(size) {
  const buf = Buffer.allocUnsafe(size);
  // buf contains uninitialized heap data — may include secrets
  return buf;
}

module.exports = { createResponse };
