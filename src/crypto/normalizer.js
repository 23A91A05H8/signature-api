'use strict';

const { InputError } = require('../errors');

/**
 * Deterministic JSON normalization (a simplified RFC 8785 / JCS):
 *   - object keys are sorted lexicographically (UTF-16 code units), recursively
 *   - no insignificant whitespace
 *   - arrays keep their order (order is semantically meaningful)
 *   - UTF-8 is preserved (no \uXXXX escaping of non-ASCII characters)
 *
 * NOTE: the serializer is hand-written on purpose. Building a "sorted" JS object
 * and calling JSON.stringify is NOT safe: JavaScript always enumerates integer-like
 * keys ("1", "2", "10") in ascending numeric order first, ignoring insertion order,
 * so two logically-equal payloads could still serialize differently.
 *
 * @param {*} value - Any JSON-compatible value.
 * @returns {string} Deterministic JSON string.
 */
function normalizeJson(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new InputError('Payload contains a non-finite number');
      }
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map(normalizeJson).join(',') + ']';
      }
      const keys = Object.keys(value).sort();
      const parts = keys.map((k) => JSON.stringify(k) + ':' + normalizeJson(value[k]));
      return '{' + parts.join(',') + '}';
    }
    default:
      throw new InputError('Payload contains a value that is not valid JSON');
  }
}

module.exports = { normalizeJson };
