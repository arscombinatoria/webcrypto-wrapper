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
});
