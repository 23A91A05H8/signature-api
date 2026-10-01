'use strict';

const crypto = require('crypto');
const { InputError } = require('../errors');
const { loadPrivateKey, digestAlgorithmFor } = require('./keys');

/**
 * Signs a normalized payload string with the provided private key.
 *
 * @param {string} normalizedPayload - Deterministically serialized JSON string.
 * @param {string} privateKeyPem     - Private key (PEM, PKCS#8 or PKCS#1).
 * @returns {string} Base64-encoded signature.
 * @throws {InputError} If the key is malformed or signing fails.
 */
function signPayload(normalizedPayload, privateKeyPem) {
  const key = loadPrivateKey(privateKeyPem);
  try {
    const data = Buffer.from(normalizedPayload, 'utf8'); // explicit UTF-8
    const signature = crypto.sign(digestAlgorithmFor(key), data, key);
    return signature.toString('base64');
  } catch (err) {
    throw new InputError('Signing failed: invalid private key');
  }
}

module.exports = { signPayload };
