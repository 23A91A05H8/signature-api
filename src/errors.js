'use strict';

/** Error that maps cleanly to an HTTP status and a safe, client-facing message. */
class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** Raised by crypto modules for bad client input (malformed key, bad Base64...). */
class InputError extends ApiError {
  constructor(message) {
    super(400, message);
    this.name = 'InputError';
  }
}

module.exports = { ApiError, InputError };
