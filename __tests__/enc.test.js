const CryptoWeb = require('../src');
const { webcrypto: nodeCrypto } = require('node:crypto');

const envs = [
  ['node', () => nodeCrypto],
  ['jsdom', () => window.crypto]
];

describe.each(envs)('Encoding helpers in %s', (name, getCrypto) => {
  const orig = global.crypto;
  beforeAll(() => { global.crypto = getCrypto(); });
  afterAll(() => { global.crypto = orig; });

  test('encoding helpers', () => {
    const msg = 'hello';
    const utf8 = CryptoWeb.enc.Utf8.parse(msg);
    const hex = CryptoWeb.enc.Hex.stringify(utf8);
    const b64 = CryptoWeb.enc.Base64.stringify(utf8);
    expect(CryptoWeb.enc.Utf8.stringify(utf8)).toBe(msg);
    expect(CryptoWeb.enc.Hex.stringify(CryptoWeb.enc.Hex.parse(hex))).toBe(hex);
    expect(CryptoWeb.enc.Base64.stringify(CryptoWeb.enc.Base64.parse(b64))).toBe(b64);
  });

  test('Base64.parse throws on invalid input', () => {
    expect(() => CryptoWeb.enc.Base64.parse('$!')).toThrow();
  });

  test('encoding helpers invalid input', () => {
    expect(() => CryptoWeb.enc.Hex.parse(null)).toThrow();
    expect(() => CryptoWeb.enc.Hex.stringify(null)).toThrow();
    expect(() => CryptoWeb.enc.Base64.parse(undefined)).toThrow();
    expect(() => CryptoWeb.enc.Base64.stringify(undefined)).toThrow();
    expect(() => CryptoWeb.enc.Utf8.stringify(null)).toThrow();
    expect(CryptoWeb.enc.Utf8.parse(undefined).length).toBe(0);
    expect(CryptoWeb.enc.Hex.stringify([])).toBe('');
    expect(CryptoWeb.enc.Base64.stringify([])).toBe('');
    expect(CryptoWeb.enc.Utf8.stringify(new Uint8Array(0))).toBe('');
  });
});
