'use strict';

const { normalizeJson } = require('../crypto/normalizer');
const { signPayload } = require('../crypto/signer');
const { InputError } = require('../errors');

function sign(req, res) {
  const body = req.body || {};
  if (!Object.prototype.hasOwnProperty.call(body, 'payload') || body.payload === undefined) {
    throw new InputError('Missing required field "payload"');
  }
  if (typeof body.privateKey !== 'string' || body.privateKey.trim() === '') {
    throw new InputError('Missing required field "privateKey"');
  }
  const normalized = normalizeJson(body.payload);
  const signature = signPayload(normalized, body.privateKey);
  res.status(200).json({ signature });
}

module.exports = { sign };
