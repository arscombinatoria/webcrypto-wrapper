const CryptoWeb = require('../src');
const vectors = require('../vectors');
const { webcrypto: nodeCrypto } = require('node:crypto');

const envs = [
  ['node', () => nodeCrypto],
  ['jsdom', () => window.crypto]
];

describe.each(envs)('PBKDF2 in %s', (name, getCrypto) => {
  const orig = global.crypto;
  beforeAll(() => { global.crypto = getCrypto(); });
  afterAll(() => { global.crypto = orig; });

  test('PBKDF2 RFC vectors', async () => {
    const { password, salt, iters } = vectors.pbkdf2;
    for (const [iter, hex] of Object.entries(iters)) {
      const res = await CryptoWeb.PBKDF2(password, salt, {
        iterations: +iter,
        keySize: 256 / 32,
        hash: 'SHA-256'
      });
      expect(res.toString()).toBe(hex);
    }
  });

  test('PBKDF2 SHA-512 vector', async () => {
    const res = await CryptoWeb.PBKDF2('password', 'salt', { iterations: 1, keySize: 20 / 4, hash: 'SHA-512' });
    expect(res.toString()).toBe('867f70cf1ade02cff3752599a3a53dc4af34c7a6');
  });

  test('PBKDF2 Uint8Array input', async () => {
    const pass = CryptoWeb.enc.Utf8.parse('pass');
    const salt = CryptoWeb.enc.Utf8.parse('salt');
    const res = await CryptoWeb.PBKDF2(pass, salt, { iterations: 1, keySize: 4 });
    expect(res.words instanceof Uint8Array).toBe(true);
  });

  test('PBKDF2 invalid iterations rejects', async () => {
    await expect(CryptoWeb.PBKDF2('p', 's', { iterations: 0 })).rejects.toThrow();
  });

  test('PBKDF2 zero keySize returns empty', async () => {
    const res = await CryptoWeb.PBKDF2('p', 's', { iterations: 1, keySize: 0 });
    expect(res.words.length).toBe(0);
  });

  test('PBKDF2 null/undefined salt rejects', async () => {
    await expect(CryptoWeb.PBKDF2('p', null)).rejects.toThrow();
    await expect(CryptoWeb.PBKDF2('p', undefined)).rejects.toThrow();
  });

  test('PBKDF2 empty salt works', async () => {
    const res = await CryptoWeb.PBKDF2('p', new Uint8Array(0), { iterations: 1 });
    expect(res.words.length).toBe(16);
  });

  test('PBKDF2 Buffer input and Array rejects', async () => {
    const bufPass = Buffer.from('password');
    const bufSalt = Buffer.from('salt');
    const a = await CryptoWeb.PBKDF2('password', 'salt', { iterations: 1, keySize: 4 });
    const b = await CryptoWeb.PBKDF2(bufPass, bufSalt, { iterations: 1, keySize: 4 });
    expect(b.toString()).toBe(a.toString());
    await expect(CryptoWeb.PBKDF2([1,2,3], [4,5,6], { iterations: 1 })).rejects.toThrow();
  });
});
