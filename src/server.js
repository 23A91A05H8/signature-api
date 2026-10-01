'use strict';

require('dotenv').config();
const { createApp } = require('./app');

const PORT = Number(process.env.PORT) || 3000;
const app = createApp();

app.listen(PORT, () => {
  console.log(`Signature API listening on http://localhost:${PORT}`);
});
