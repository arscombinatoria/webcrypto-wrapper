const CryptoWeb = require('../src');
const { webcrypto: nodeCrypto } = require('node:crypto');

const envs = [
  ['node', () => nodeCrypto],
  ['jsdom', () => window.crypto]
];

describe.each(envs)('AES error/boundary cases in %s', (name, getCrypto) => {
  const orig = global.crypto;
  beforeAll(() => { global.crypto = getCrypto(); });
  afterAll(() => { global.crypto = orig; jest.restoreAllMocks(); });

  test('AES invalid parameters', async () => {
    await expect(CryptoWeb.AES.encrypt('x', new Uint8Array(5))).rejects.toThrow('Key length');
    await expect(CryptoWeb.AES.decrypt('abcd', 'deadbeef')).rejects.toThrow('salt required');
    const keyHex = '00112233445566778899aabbccddeeff';
    await expect(CryptoWeb.AES.encrypt([1,2,3], keyHex)).rejects.toThrow();
    await expect(CryptoWeb.AES.decrypt({ ciphertext: [1,2,3], iv: '000102030405060708090a0b0c0d0e0f' }, keyHex)).rejects.toThrow();
    await expect(CryptoWeb.AES.encrypt(null, keyHex)).rejects.toThrow();
    await expect(CryptoWeb.AES.encrypt(undefined, keyHex)).rejects.toThrow();
    await expect(CryptoWeb.AES.decrypt('abcd', keyHex)).rejects.toThrow('IV required');
    await expect(CryptoWeb.AES.decrypt({ ciphertext: new Uint8Array([1,2,3]) }, keyHex)).rejects.toThrow('IV required');
    await expect(CryptoWeb.AES.decrypt(null, keyHex)).rejects.toThrow('invalid ciphertext');
    await expect(CryptoWeb.AES.decrypt(undefined, keyHex)).rejects.toThrow('invalid ciphertext');
    await expect(CryptoWeb.AES.decrypt(new Uint8Array(0), keyHex)).rejects.toThrow('invalid ciphertext');
  });

  test('getRandomValues instance reused for IV', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const wc = require('node:crypto').webcrypto;
    const spy = jest.spyOn(wc, 'getRandomValues').mockImplementation(arr => { arr.fill(0xAA); return arr; });
    const enc = await CryptoWeb.AES.encrypt('hello', key);
    const passed = spy.mock.calls[0][0];
    expect(enc.iv.words).toBe(passed);
    expect(spy.mock.results[0].value).toBe(passed);
    spy.mockRestore();
  });

  test('AES empty string round trip', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const enc = await CryptoWeb.AES.encrypt('', key, { iv });
    expect(enc.ciphertext.words.length).toBe(16);
    const dec = await CryptoWeb.AES.decrypt(enc, key);
    expect(dec.toString()).toBe('');
  });

  test('AES empty array round trip', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const enc = await CryptoWeb.AES.encrypt(new Uint8Array(0), key);
    const dec = await CryptoWeb.AES.decrypt(enc, key);
    expect(dec.words.length).toBe(0);
  });

  test('AES auto IV round trip', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const enc = await CryptoWeb.AES.encrypt('x', key);
    const dec = await CryptoWeb.AES.decrypt(enc, key);
    expect(dec.toString()).toBe('x');
  });

  test('AES string round trip with embedded IV', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const enc = await CryptoWeb.AES.encrypt('hello', key);
    const dec = await CryptoWeb.AES.decrypt(enc.toString(), key);
    expect(dec.toString()).toBe('hello');
  });

  test('AES decrypt with wrong key or IV fails', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const badKey = '112233445566778899aabbccddeeff00';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const enc = await CryptoWeb.AES.encrypt('data', key, { iv });
    await expect(CryptoWeb.AES.decrypt(enc, badKey)).rejects.toThrow();
    await expect(CryptoWeb.AES.decrypt({ ciphertext: enc.ciphertext, iv: 'ffeeddccbbaa99887766554433221100' }, key)).rejects.toThrow();
  });

  test('AES invalid IV length', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const iv15 = CryptoWeb.enc.Hex.parse('00'.repeat(30));
    const iv17 = CryptoWeb.enc.Hex.parse('00'.repeat(34));
    await expect(CryptoWeb.AES.encrypt('x', key, { iv: iv15 })).rejects.toThrow();
    await expect(CryptoWeb.AES.encrypt('x', key, { iv: iv17 })).rejects.toThrow();
    const enc = await CryptoWeb.AES.encrypt('x', key);
    await expect(CryptoWeb.AES.decrypt({ ciphertext: enc.ciphertext, iv: iv15 }, key)).rejects.toThrow();
    await expect(CryptoWeb.AES.decrypt({ ciphertext: enc.ciphertext, iv: iv17 }, key)).rejects.toThrow();
  });

  test('AES decrypt propagates subtle errors', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const enc = await CryptoWeb.AES.encrypt('hello', key, { iv });
    const tampered = enc.ciphertext.words.slice();
    tampered[0] ^= 1;
    await expect(CryptoWeb.AES.decrypt({ ciphertext: tampered, iv }, key)).rejects.toThrow();
  });

  test('AES decrypt invalid ciphertext sizes', async () => {
    const key = '00112233445566778899aabbccddeeff';
    await expect(CryptoWeb.AES.decrypt('', key)).rejects.toThrow('IV required');
    const iv = '000102030405060708090a0b0c0d0e0f';
    await expect(CryptoWeb.AES.decrypt('AA==', key, { iv })).rejects.toThrow();
  });

  test('AES 1MiB round trip', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const data = new Uint8Array(1 << 20).fill(0);
    const enc = await CryptoWeb.AES.encrypt(data, key);
    const dec = await CryptoWeb.AES.decrypt(enc, key);
    expect(dec.words.length).toBe(data.length);
  });

  test('AES block size boundary lengths', async () => {
    const key = '00112233445566778899aabbccddeeff';
    for (const len of [15, 16, 17]) {
      const data = new Uint8Array(len).fill(0);
      const enc = await CryptoWeb.AES.encrypt(data, key);
      const dec = await CryptoWeb.AES.decrypt(enc, key);
      expect(dec.words.length).toBe(len);
    }
  });

  test('AES >10MiB round trip', async () => {
    const key = '00112233445566778899aabbccddeeff';
    const data = new Uint8Array((10 << 20) + 1).fill(0);
    const enc = await CryptoWeb.AES.encrypt(data, key);
    const dec = await CryptoWeb.AES.decrypt(enc, key);
    expect(dec.words.length).toBe(data.length);
  });
});
