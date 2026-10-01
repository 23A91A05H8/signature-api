'use strict';

const { normalizeJson } = require('../crypto/normalizer');
const { verifySignature } = require('../crypto/verifier');
const { InputError } = require('../errors');

function verify(req, res) {
  const body = req.body || {};
  if (!Object.prototype.hasOwnProperty.call(body, 'payload') || body.payload === undefined) {
    throw new InputError('Missing required field "payload"');
  }
  if (typeof body.signature !== 'string' || body.signature === '') {
    throw new InputError('Missing required field "signature"');
  }
  if (typeof body.publicKey !== 'string' || body.publicKey.trim() === '') {
    throw new InputError('Missing required field "publicKey"');
  }
  const normalized = normalizeJson(body.payload);
  const isValid = verifySignature(normalized, body.signature, body.publicKey);
  res.status(200).json({ isValid });
}

module.exports = { verify };
