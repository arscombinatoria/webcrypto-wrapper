const { webcrypto: nodeCrypto } = require('node:crypto');

test('randomBytes fallback when getRandomValues missing', async () => {
  jest.resetModules();
  const crypto = require('node:crypto');
  const orig = crypto.webcrypto.getRandomValues;
  crypto.webcrypto.getRandomValues = undefined;
  global.crypto = crypto.webcrypto;
  const spy = jest.spyOn(crypto, 'randomBytes');
  let CW;
  jest.isolateModules(() => {
    CW = require('../src');
  });
  await CW.AES.encrypt('x', '00112233445566778899aabbccddeeff');
  expect(spy).toHaveBeenCalled();
  spy.mockRestore();
  crypto.webcrypto.getRandomValues = orig;
  global.crypto = nodeCrypto;
});

test('MD5 JavaScript fallback', async () => {
  jest.resetModules();
  const crypto = require('node:crypto');
  const orig = crypto.createHash;
  delete crypto.createHash;
  let CW;
  jest.isolateModules(() => {
    CW = require('../src');
  });
  const h = await CW.MD5('abc');
  expect(h.toString().length).toBe(32);
  crypto.createHash = orig;
});
