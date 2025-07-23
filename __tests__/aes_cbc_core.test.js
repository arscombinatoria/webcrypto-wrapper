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

  test('AES encrypt/decrypt with Buffer', async () => {
    const v = vectors.aesCbc[0];
    const pt = Buffer.from(v.pt, 'hex');
    const key = Buffer.from(v.key, 'hex');
    const iv = Buffer.from(v.iv, 'hex');
    const enc = await CryptoWeb.AES.encrypt(pt, key, { iv });
    const hex = enc.ciphertext.toString(CryptoWeb.enc.Hex);
    expect(hex.slice(0, v.ct.length)).toBe(v.ct);
    const dec = await CryptoWeb.AES.decrypt(enc, key);
    expect(CryptoWeb.enc.Hex.stringify(dec.words)).toBe(v.pt);
  });

  test('AES padding round trip', async () => {
    const key = '00112233445566778899aabbccddeeff';
    for (const len of [16, 15, 23]) {
      const data = Uint8Array.from({ length: len }, (_, i) => i);
      const enc = await CryptoWeb.AES.encrypt(data, key);
      const dec = await CryptoWeb.AES.decrypt(enc, key);
      expect(Array.from(dec.words)).toEqual(Array.from(data));
    }
  });

  test('passphrase salt variations and CryptoJS compatibility', async () => {
    const salt = '01020304';
    const pw = 'pass';
    const enc = await CryptoWeb.AES.encrypt('hello', pw, { salt });
    const cjEnc = CryptoJS.AES.encrypt('hello', pw, { salt: CryptoJS.enc.Hex.parse(salt) });
    expect(enc.toString()).toBe(cjEnc.toString());
    await expect(CryptoWeb.AES.decrypt(enc.toString(), pw)).rejects.toThrow();
    const b64 = enc.ciphertext.toString(CryptoWeb.enc.Base64);
    const dec = await CryptoWeb.AES.decrypt(b64, pw, { salt });
    expect(dec.toString()).toBe('hello');
    await expect(CryptoWeb.AES.decrypt(cjEnc.toString(), pw)).rejects.toThrow();
  });

  test('string ciphertext without IV and cfg.iv priority', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const enc = await CryptoWeb.AES.encrypt('hello', key, { iv });
    const ctOnly = enc.ciphertext.toString(CryptoWeb.enc.Base64);
    const dec = await CryptoWeb.AES.decrypt(ctOnly, key, { iv });
    expect(dec.toString()).toBe('hello');
    const wrong = 'ffeeddccbbaa99887766554433221100';
    await expect(CryptoWeb.AES.decrypt(enc.toString(), key, { iv: wrong })).rejects.toThrow();
  });

  test('mixed word array and Uint8Array object input', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const enc = await CryptoWeb.AES.encrypt('hi', key);
    const obj1 = { ciphertext: enc.ciphertext.words, iv: enc.iv };
    const dec1 = await CryptoWeb.AES.decrypt(obj1, key);
    expect(dec1.toString()).toBe('hi');
    const obj2 = { ciphertext: enc.ciphertext, iv: enc.iv.words };
    const dec2 = await CryptoWeb.AES.decrypt(obj2, key);
    expect(dec2.toString()).toBe('hi');
  });
});
