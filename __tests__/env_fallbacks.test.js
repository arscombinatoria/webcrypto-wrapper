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

test('Base64 Buffer fallback when atob/btoa missing', () => {
  jest.resetModules();
  const origAtob = global.atob;
  const origBtoa = global.btoa;
  global.atob = undefined;
  global.btoa = undefined;
  let CW;
  jest.isolateModules(() => {
    CW = require('../src');
  });
  const b64 = CW.enc.Base64.stringify(Uint8Array.from([104, 105]));
  expect(b64).toBe('aGk=');
  const bytes = CW.enc.Base64.parse(b64);
  expect(CW.enc.Utf8.stringify(bytes)).toBe('hi');
  global.atob = origAtob;
  global.btoa = origBtoa;
});

test('throws when no secure random generator', async () => {
  jest.resetModules();
  const crypto = require('node:crypto');
  const origGRV = crypto.webcrypto.getRandomValues;
  const origRB = crypto.randomBytes;
  crypto.webcrypto.getRandomValues = undefined;
  delete crypto.randomBytes;
  global.crypto = crypto.webcrypto;
  let CW;
  jest.isolateModules(() => {
    CW = require('../src');
  });
  await expect(
    CW.AES.encrypt('x', '00112233445566778899aabbccddeeff')
  ).rejects.toThrow('No secure random generator');
  crypto.webcrypto.getRandomValues = origGRV;
  crypto.randomBytes = origRB;
  global.crypto = nodeCrypto;
});

test('works with ESM import and UMD global path', async () => {
  jest.resetModules();
  const cwReq = require('../src');
  expect(cwReq.AES).toBeDefined();

  const { execFileSync } = require('child_process');
  const out = execFileSync(process.execPath, ['-e', "import('./src/index.js').then(()=>console.log('ok'))"], { cwd: __dirname + '/..' });
  expect(out.toString().trim()).toBe('ok');

  const fs = require('fs');
  const vm = require('vm');
  const code = fs.readFileSync(require.resolve('../src/index.js'), 'utf8');
  const ctx = { self: { crypto: { subtle: {} } }, Buffer, TextEncoder, TextDecoder };
  vm.runInNewContext(code, ctx);
  expect(ctx.self.CryptoWeb).toBeDefined();
});

test('throws on load when crypto.subtle missing', () => {
  const fs = require('fs');
  const vm = require('vm');
  const code = fs.readFileSync(require.resolve('../src/index.js'), 'utf8');
  const ctx = { self: { crypto: {} } };
  expect(() => vm.runInNewContext(code, ctx)).toThrow('WebCrypto not available');
});
