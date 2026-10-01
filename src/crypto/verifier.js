'use strict';

const crypto = require('crypto');
const { InputError } = require('../errors');
const { loadPublicKey, digestAlgorithmFor } = require('./keys');

// Strict, padded standard Base64. Node's Buffer.from(..., 'base64') silently
// ignores invalid characters, so we validate explicitly instead.
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Strictly decodes a Base64 string.
 * @throws {InputError} "Malformed Base64 signature"
 */
function decodeBase64Strict(value) {
  if (typeof value !== 'string' || value.length === 0 || !BASE64_RE.test(value)) {
    throw new InputError('Malformed Base64 signature');
  }
  return Buffer.from(value, 'base64');
}

/**
 * Verifies a signature over a normalized payload.
 *
 * @param {string} normalizedPayload - Deterministically serialized JSON string.
 * @param {string} signatureB64      - Base64-encoded signature.
 * @param {string} publicKeyPem      - Public key (PEM, SPKI).
 * @returns {boolean} true if valid, false if the signature does not match.
 * @throws {InputError} For malformed Base64 or a malformed public key (-> HTTP 400).
 */
function verifySignature(normalizedPayload, signatureB64, publicKeyPem) {
  const signature = decodeBase64Strict(signatureB64);
  const key = loadPublicKey(publicKeyPem);
  try {
    const data = Buffer.from(normalizedPayload, 'utf8');
    // crypto.verify performs the comparison in the underlying library
    // (constant-time); we never compare signatures manually.
    return crypto.verify(digestAlgorithmFor(key), data, key, signature);
  } catch (err) {
    // e.g. signature of the wrong length/format for this key type.
    return false;
  }
}

module.exports = { verifySignature, decodeBase64Strict };
