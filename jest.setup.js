const { webcrypto } = require('node:crypto');
const { TextEncoder, TextDecoder } = require('util');

Object.defineProperty(global, 'crypto', {
  value: webcrypto,
  configurable: true,
  writable: true
});
Object.assign(global, { TextEncoder, TextDecoder });
