const CryptoWeb = require('../src');
const CryptoJS = require('crypto-js');
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

  test('PBKDF2 hash algorithm variations', async () => {
    const vectors = {
      'SHA-1': '0c60c80f961f0e71f3a9b524af6012062fe037a6',
      'SHA-256': '120fb6cffcf8b32c43e7225256c4f837a86548c9',
      'SHA-384': 'c0e14f06e49e32d73f9f52ddf1d0c5c719160923',
      'SHA-512': '867f70cf1ade02cff3752599a3a53dc4af34c7a6'
    };
    for (const [hash, hex] of Object.entries(vectors)) {
      const res = await CryptoWeb.PBKDF2('password', 'salt', { iterations: 1, keySize: 20 / 4, hash });
      expect(res.toString()).toBe(hex);
    }
  });

  test('PBKDF2 iterations boundary and type', async () => {
    const a = await CryptoWeb.PBKDF2('p', 's', { iterations: 1, keySize: 4 });
    const b = await CryptoWeb.PBKDF2('p', 's', { iterations: 1.5, keySize: 4 });
    expect(b.toString()).toBe(a.toString());
    await expect(CryptoWeb.PBKDF2('p', 's', { iterations: -1 })).rejects.toThrow();
  });

  test('PBKDF2 keySize edge cases', async () => {
    const half = await CryptoWeb.PBKDF2('p', 's', { iterations: 1, keySize: 0.5 });
    expect(half.words.length).toBe(2);
    const large = await CryptoWeb.PBKDF2('p', 's', { iterations: 1, keySize: 1024 });
    expect(large.words.length).toBe(4096);
  });

  test('PBKDF2 Uint8Array vs string equality', async () => {
    const passBytes = CryptoWeb.enc.Utf8.parse('pass');
    const saltBytes = CryptoWeb.enc.Utf8.parse('salt');
    const a = await CryptoWeb.PBKDF2('pass', 'salt', { iterations: 2, keySize: 4 });
    const b = await CryptoWeb.PBKDF2(passBytes, saltBytes, { iterations: 2, keySize: 4 });
    expect(b.toString()).toBe(a.toString());
  });

  test('PBKDF2 matches CryptoJS implementation', async () => {
    const opts = { iterations: 10, keySize: 4, hash: 'SHA-256' };
    const cw = await CryptoWeb.PBKDF2('password', 'salt', opts);
    const cj = CryptoJS.PBKDF2('password', 'salt', {
      iterations: opts.iterations,
      keySize: opts.keySize,
      hasher: CryptoJS.algo.SHA256
    });
    expect(cw.toString()).toBe(cj.toString());
  });
});
