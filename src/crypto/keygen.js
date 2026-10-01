'use strict';

const crypto = require('crypto');
const { InputError } = require('../errors');

const SUPPORTED = ['rsa', 'ed25519'];

/**
 * Generates a secure asymmetric key pair and exports it as PEM strings.
 *
 * @param {string} [algorithm='rsa'] - 'rsa' or 'ed25519'.
 * @param {number} [rsaBits=2048]    - RSA modulus length (>= 2048).
 * @returns {{publicKey: string, privateKey: string}}
 */
function generateKeyPair(algorithm, rsaBits) {
  const alg = String(algorithm || process.env.DEFAULT_KEY_ALGORITHM || 'rsa').toLowerCase();
  if (!SUPPORTED.includes(alg)) {
    throw new InputError(`Unsupported algorithm. Use one of: ${SUPPORTED.join(', ')}`);
  }

  const encodings = {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  };

  if (alg === 'ed25519') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', encodings);
    return { publicKey, privateKey };
  }

  const bits = Number(rsaBits || process.env.RSA_MODULUS_LENGTH || 2048);
  if (!Number.isInteger(bits) || bits < 2048 || bits > 8192) {
    throw new InputError('RSA modulus length must be an integer between 2048 and 8192');
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    ...encodings,
  });
  return { publicKey, privateKey };
}

module.exports = { generateKeyPair, SUPPORTED };
