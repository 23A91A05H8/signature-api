'use strict';

const { generateKeyPair } = require('../crypto/keygen');
const { InputError } = require('../errors');

function generateKeys(req, res) {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  // Optional: { "algorithm": "rsa" | "ed25519" }. No body is required.
  if (body.algorithm !== undefined && typeof body.algorithm !== 'string') {
    throw new InputError('"algorithm" must be a string');
  }
  const { publicKey, privateKey } = generateKeyPair(body.algorithm);
  res.status(200).json({ publicKey, privateKey });
}

module.exports = { generateKeys };
