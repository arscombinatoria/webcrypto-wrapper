const CryptoWeb = require('../src');
const CryptoJS = require('crypto-js');
const vectors = require('../vectors');
const { webcrypto: nodeCrypto } = require('node:crypto');

const envs = [
  ['node', () => nodeCrypto],
  ['jsdom', () => window.crypto]
];

describe.each(envs)('AES core in %s', (name, getCrypto) => {
  const orig = global.crypto;
  beforeAll(() => {
    global.crypto = getCrypto();
    jest.spyOn(global.crypto, 'getRandomValues').mockImplementation(arr => {
      arr.set(Uint8Array.from({ length: arr.length }, (_, i) => i + 1));
      return arr;
    });
  });
  afterAll(() => { global.crypto = orig; jest.restoreAllMocks(); });

  test('AES NIST vectors', async () => {
    for (const v of vectors.aesCbc) {
      const pt = CryptoWeb.enc.Hex.parse(v.pt);
      const r = await CryptoWeb.AES.encrypt(pt, v.key, { iv: v.iv });
      const hex = r.ciphertext.toString(CryptoWeb.enc.Hex);
      expect(hex.slice(0, v.ct.length)).toBe(v.ct);
      const dec = await CryptoWeb.AES.decrypt(r, v.key);
      expect(CryptoWeb.enc.Hex.stringify(dec.words)).toBe(v.pt);
    }
  });

  test('EVP_BytesToKey compatibility', async () => {
    const enc = await CryptoWeb.AES.encrypt('Hello', 'secret', { salt: vectors.evp.salt });
    expect(enc.iv.toString(CryptoWeb.enc.Hex).toUpperCase()).toBe(vectors.evp.iv);
    expect(enc.toString()).toBe(vectors.evp.cipher);
    const dec = await CryptoWeb.AES.decrypt(enc.toString(), 'secret');
    expect(dec.toString()).toBe('Hello');
  });

  test('AES encrypt result matches CryptoJS without IV', async () => {
    const salt = '0102030405060708';
    const cwAuto = await CryptoWeb.AES.encrypt('auto', 'p@ss', { salt });
    const cjAuto = CryptoJS.AES.encrypt('auto', 'p@ss', { salt: CryptoJS.enc.Hex.parse(salt) });
    expect(cwAuto.toString()).toBe(cjAuto.toString());
  });

  test('UTF-8 surrogate pair encryption', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const str = '😀'.repeat(5);
    const iv = '000102030405060708090a0b0c0d0e0f';
    const enc = await CryptoWeb.AES.encrypt(str, key, { iv });
    const dec = await CryptoWeb.AES.decrypt(enc, key);
    expect(dec.toString()).toBe(str);
  });
});
