'use strict';

function health(req, res) {
  res.status(200).json({ status: 'ok' });
}

module.exports = { health };
