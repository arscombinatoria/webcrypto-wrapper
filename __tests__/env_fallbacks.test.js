const { webcrypto: nodeCrypto } = require('node:crypto');

const restoreNodeWebcrypto = () => {
  global.crypto = nodeCrypto;
};

afterEach(() => {
  vi.restoreAllMocks();
  restoreNodeWebcrypto();
});

test('randomBytes fallback when getRandomValues missing', async () => {
  vi.resetModules();
  const crypto = require('node:crypto');
  const orig = crypto.webcrypto.getRandomValues;
  crypto.webcrypto.getRandomValues = undefined;
  global.crypto = crypto.webcrypto;
  const deterministicIv = Buffer.alloc(16, 0xaa);
  const spy = vi.spyOn(crypto, 'randomBytes').mockReturnValue(deterministicIv);

  try {
    const CW = require('../src');
    const encrypted = await CW.AES.encrypt('x', '00112233445566778899aabbccddeeff');

    expect(spy).toHaveBeenCalledWith(16);
    expect(encrypted.iv.toString(CW.enc.Hex)).toBe('aa'.repeat(16));
  } finally {
    crypto.webcrypto.getRandomValues = orig;
  }
});

test('MD5 JavaScript fallback computes the standard digest', async () => {
  vi.resetModules();
  const crypto = require('node:crypto');
  const orig = crypto.createHash;
  delete crypto.createHash;

  try {
    const CW = require('../src');
    const h = await CW.MD5('abc');

    expect(h.toString()).toBe('900150983cd24fb0d6963f7d28e17f72');
  } finally {
    crypto.createHash = orig;
  }
});

test('Base64 Buffer fallback when atob/btoa missing', () => {
  vi.resetModules();
  const origAtob = global.atob;
  const origBtoa = global.btoa;
  global.atob = undefined;
  global.btoa = undefined;

  try {
    const CW = require('../src');
    const b64 = CW.enc.Base64.stringify(Uint8Array.from([104, 105]));
    expect(b64).toBe('aGk=');
    const bytes = CW.enc.Base64.parse(b64);
    expect(CW.enc.Utf8.stringify(bytes)).toBe('hi');
  } finally {
    global.atob = origAtob;
    global.btoa = origBtoa;
  }
});

test('throws when no secure random generator', async () => {
  vi.resetModules();
  const crypto = require('node:crypto');
  const origGRV = crypto.webcrypto.getRandomValues;
  const origRB = crypto.randomBytes;
  crypto.webcrypto.getRandomValues = undefined;
  delete crypto.randomBytes;
  global.crypto = crypto.webcrypto;

  try {
    const CW = require('../src');
    await expect(
      CW.AES.encrypt('x', '00112233445566778899aabbccddeeff')
    ).rejects.toThrow('No secure random generator');
  } finally {
    crypto.webcrypto.getRandomValues = origGRV;
    crypto.randomBytes = origRB;
  }
});

test('works with ESM import and UMD global path', async () => {
  vi.resetModules();
  const cwReq = require('../src');
  expect(cwReq.AES).toBeDefined();

  const { execFileSync } = require('child_process');
  const out = execFileSync(process.execPath, ['-e', "import('./src/index.js').then((mod)=>console.log(typeof mod.default.AES.encrypt))"], { cwd: __dirname + '/..' });
  expect(out.toString().trim()).toBe('function');

  const fs = require('fs');
  const vm = require('vm');
  const code = fs.readFileSync(require.resolve('../src/index.js'), 'utf8');
  const ctx = { self: { crypto: { subtle: {} } }, Buffer, TextEncoder, TextDecoder };
  vm.runInNewContext(code, ctx);
  expect(ctx.self.CryptoWeb.AES.encrypt).toBeTypeOf('function');
});

test('throws on load when crypto.subtle missing', () => {
  const fs = require('fs');
  const vm = require('vm');
  const code = fs.readFileSync(require.resolve('../src/index.js'), 'utf8');
  const ctx = { self: { crypto: {} } };
  expect(() => vm.runInNewContext(code, ctx)).toThrow('WebCrypto not available');
});
