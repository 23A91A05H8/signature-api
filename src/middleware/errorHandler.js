'use strict';

const { ApiError } = require('../errors');

function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

/**
 * Central error handler. Never leaks stack traces or crypto-library internals.
 */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err instanceof ApiError) {
    return res.status(err.status).json({ error: err.message });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large' });
  }
  if (err && err.status && err.status >= 400 && err.status < 500) {
    return res.status(err.status).json({ error: 'Bad request' });
  }
  console.error('Unexpected error:', err && err.message); // message only, server-side
  return res.status(500).json({ error: 'Internal server error' });
}

module.exports = { notFound, errorHandler };
