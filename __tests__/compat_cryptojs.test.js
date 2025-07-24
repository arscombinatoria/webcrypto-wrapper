const CryptoWeb = require('../src');
const CryptoJS = require('crypto-js');
const vectors = require('../vectors');
const { webcrypto: nodeCrypto } = require('node:crypto');

const envs = [
  ['node', () => nodeCrypto],
  ['jsdom', () => window.crypto]
];

describe.each(envs)('CryptoJS compatibility in %s', (name, getCrypto) => {
  const orig = global.crypto;
  beforeAll(() => { global.crypto = getCrypto(); });
  afterAll(() => { global.crypto = orig; });

  test('CryptoWeb <-> CryptoJS', async () => {
    const keyHex = (await CryptoWeb.PBKDF2('password', 'salt', {
      keySize: 256 / 32,
      iterations: 1000
    })).toString();
    const ivHex = '000102030405060708090a0b0c0d0e0f';

    const cwEnc = await CryptoWeb.AES.encrypt('secret', keyHex, { iv: ivHex });
    const cwCtWA = CryptoJS.enc.Hex.parse(cwEnc.ciphertext.toString());
    const cwIvWA = CryptoJS.enc.Hex.parse(cwEnc.iv.toString());
    const cjDec = CryptoJS.AES.decrypt({ ciphertext: cwCtWA }, CryptoJS.enc.Hex.parse(keyHex), { iv: cwIvWA });
    expect(cjDec.toString(CryptoJS.enc.Utf8)).toBe('secret');

    const cjEncSame = CryptoJS.AES.encrypt('secret', CryptoJS.enc.Hex.parse(keyHex), { iv: cwIvWA });
    expect(cwEnc.ciphertext.toString(CryptoWeb.enc.Base64)).toBe(cjEncSame.toString());

    const cjEnc = CryptoJS.AES.encrypt('secret', CryptoJS.enc.Hex.parse(keyHex), { iv: cwIvWA });
    const webDec = await CryptoWeb.AES.decrypt(cjEnc.toString(), keyHex, { iv: ivHex });
    expect(webDec.toString()).toBe('secret');

    const saltWA = CryptoJS.lib.WordArray.random(8);
    const saltHex = saltWA.toString();
    const cjEncPw = CryptoJS.AES.encrypt('hello', 'pass', { salt: saltWA });
    const cwEncPw = await CryptoWeb.AES.encrypt('hello', 'pass', { salt: saltHex });
    expect(cwEncPw.toString()).toBe(cjEncPw.toString());
    expect((await CryptoWeb.AES.decrypt(cjEncPw.toString(), 'pass')).toString()).toBe('hello');
    const cjDecPw = CryptoJS.AES.decrypt(cwEncPw.toString(), 'pass');
    expect(cjDecPw.toString(CryptoJS.enc.Utf8)).toBe('hello');
  });

  test('hash functions match CryptoJS', async () => {
    const data = 'abc';
    const hashes = {
      sha1: await CryptoWeb.SHA1(data),
      sha256: await CryptoWeb.SHA256(data),
      sha384: await CryptoWeb.SHA384(data),
      sha512: await CryptoWeb.SHA512(data),
      md5: await CryptoWeb.MD5(data)
    };
    expect(hashes.sha1.toString()).toBe(CryptoJS.SHA1(data).toString());
    expect(hashes.sha256.toString()).toBe(CryptoJS.SHA256(data).toString());
    expect(hashes.sha384.toString()).toBe(CryptoJS.SHA384(data).toString());
    expect(hashes.sha512.toString()).toBe(CryptoJS.SHA512(data).toString());
    expect(hashes.md5.toString()).toBe(CryptoJS.MD5(data).toString());
  });

  test('PBKDF2 matches CryptoJS for each hash', async () => {
    const algos = [
      ['SHA-1', CryptoJS.algo.SHA1],
      ['SHA-256', CryptoJS.algo.SHA256],
      ['SHA-384', CryptoJS.algo.SHA384],
      ['SHA-512', CryptoJS.algo.SHA512]
    ];
    for (const [name, algo] of algos) {
      const opts = { iterations: 10, keySize: 4, hash: name };
      const cw = await CryptoWeb.PBKDF2('password', 'salt', opts);
      const cj = CryptoJS.PBKDF2('password', 'salt', {
        iterations: opts.iterations,
        keySize: opts.keySize,
        hasher: algo
      });
      expect(cw.toString()).toBe(cj.toString());
    }
  });

  test('encoding interoperability with CryptoJS', () => {
    const str = 'hi';
    const cwUtf8 = CryptoWeb.enc.Utf8.parse(str);
    const cjUtf8 = CryptoJS.enc.Utf8.parse(str);
    expect(CryptoWeb.enc.Hex.stringify(cwUtf8)).toBe(cjUtf8.toString());
    const hex = cjUtf8.toString();
    const cwFromHex = CryptoWeb.enc.Hex.parse(hex);
    expect(CryptoWeb.enc.Utf8.stringify(cwFromHex)).toBe(str);
    expect(CryptoWeb.enc.Base64.stringify(cwFromHex)).toBe(cjUtf8.toString(CryptoJS.enc.Base64));
    const b64 = CryptoJS.enc.Base64.stringify(cjUtf8);
    const cwFromB64 = CryptoWeb.enc.Base64.parse(b64);
    expect(CryptoWeb.enc.Hex.stringify(cwFromB64)).toBe(hex);
  });

  test('AES ciphertext toString in Base64 and Hex', async () => {
    const key = (await CryptoWeb.PBKDF2('pass', 'salt', { keySize: 256 / 32, iterations: 1 })).toString();
    const iv = '000102030405060708090a0b0c0d0e0f';
    const cwEnc = await CryptoWeb.AES.encrypt('data', key, { iv });
    const cjEnc = CryptoJS.AES.encrypt('data', CryptoJS.enc.Hex.parse(key), { iv: CryptoJS.enc.Hex.parse(iv) });
    expect(cwEnc.ciphertext.toString(CryptoWeb.enc.Base64)).toBe(cjEnc.toString());
    expect(cwEnc.ciphertext.toString(CryptoWeb.enc.Hex)).toBe(cjEnc.ciphertext.toString());
  });

  test('Salted__ roundtrip CryptoJS -> CryptoWeb -> CryptoJS', async () => {
    const cjEnc = CryptoJS.AES.encrypt('round', 'secret');
    const dec = await CryptoWeb.AES.decrypt(cjEnc.toString(), 'secret');
    expect(dec.toString()).toBe('round');
    const cwEnc = await CryptoWeb.AES.encrypt('round', 'secret', { salt: cjEnc.salt.toString() });
    expect(cwEnc.toString()).toBe(cjEnc.toString());
    const cjDec = CryptoJS.AES.decrypt(cwEnc.toString(), 'secret');
    expect(cjDec.toString(CryptoJS.enc.Utf8)).toBe('round');
  });
});
