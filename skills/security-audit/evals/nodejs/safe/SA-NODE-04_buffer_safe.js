// SA-NODE-04: safe buffer allocation with zero-filled memory
function createResponse(size) {
  const MAX_SIZE = 1024 * 1024;
  if (size < 0 || size > MAX_SIZE) {
    throw new Error('Invalid buffer size');
  }
  const buf = Buffer.alloc(size);
  return buf;
}

module.exports = { createResponse };
