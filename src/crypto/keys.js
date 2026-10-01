'use strict';

const crypto = require('crypto');
const { InputError } = require('../errors');

/**
 * JSON transports often carry PEM newlines as a literal backslash-n. Restore real
 * newlines so the PEM headers stay intact, and trim surrounding whitespace.
 */
function cleanPem(pem) {
  return String(pem).replace(/\\r\\n|\\n/g, '\n').trim();
}

function assertPemString(value, fieldName) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new InputError(`Missing or invalid "${fieldName}"`);
  }
}

function assertSupported(key, kind) {
  const type = key.asymmetricKeyType;
  if (type !== 'rsa' && type !== 'ed25519') {
    throw new InputError(`Unsupported ${kind} key type. Use RSA or Ed25519`);
  }
  if (type === 'rsa' && key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength < 2048) {
    throw new InputError('RSA keys must be at least 2048 bits');
  }
}

/** Parses a PEM private key; throws InputError("Invalid private key format"). */
function loadPrivateKey(pem) {
  assertPemString(pem, 'privateKey');
  const cleaned = cleanPem(pem);
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(cleaned)) {
    throw new InputError('Invalid private key format');
  }
  try {
    const key = crypto.createPrivateKey(cleaned);
    assertSupported(key, 'private');
    return key;
  } catch (err) {
    if (err instanceof InputError) throw err;
    throw new InputError('Invalid private key format');
  }
}

/** Parses a PEM public key; throws InputError("Invalid public key format"). */
function loadPublicKey(pem) {
  assertPemString(pem, 'publicKey');
  const cleaned = cleanPem(pem);
  // Refuse to silently derive a public key from a private one.
  if (/PRIVATE KEY-----/.test(cleaned) || !/-----BEGIN [A-Z ]*PUBLIC KEY-----/.test(cleaned)) {
    throw new InputError('Invalid public key format');
  }
  try {
    const key = crypto.createPublicKey(cleaned);
    assertSupported(key, 'public');
    return key;
  } catch (err) {
    if (err instanceof InputError) throw err;
    throw new InputError('Invalid public key format');
  }
}

/**
 * RSA signs/verifies with SHA-256 (the library hashes internally - we never
 * pre-hash, which would cause double hashing). Ed25519 is a "pure" scheme and
 * must be given algorithm = null; it hashes internally with SHA-512.
 */
function digestAlgorithmFor(key) {
  return key.asymmetricKeyType === 'ed25519' ? null : 'sha256';
}

module.exports = { loadPrivateKey, loadPublicKey, digestAlgorithmFor };
