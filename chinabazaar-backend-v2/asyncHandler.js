// Async route handler sarmalayıcı — hataları Express error middleware'e iletir
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

module.exports = asyncHandler;
