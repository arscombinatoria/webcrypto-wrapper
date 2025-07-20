const { webcrypto } = require('node:crypto');
const { TextEncoder, TextDecoder } = require('util');

global.crypto = webcrypto;
Object.assign(global, { TextEncoder, TextDecoder });
