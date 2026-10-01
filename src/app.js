'use strict';

const express = require('express');
const { generateKeys } = require('./controllers/keys.controller');
const { sign } = require('./controllers/sign.controller');
const { verify } = require('./controllers/verify.controller');
const { health } = require('./controllers/health.controller');
const { notFound, errorHandler } = require('./middleware/errorHandler');

function createApp() {
  const app = express();
  app.disable('x-powered-by');

  // Payload limit protects against DoS during hashing/signing.
  app.use(express.json({ limit: process.env.BODY_LIMIT || '1mb' }));

  app.get('/api/health', health);
  app.post('/api/keys/generate', generateKeys);
  app.post('/api/sign', sign);
  app.post('/api/verify', verify);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}

module.exports = { createApp };
