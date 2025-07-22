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

  test('encoding helpers with ArrayLike input', () => {
    const bytes = [0x68, 0x69];
    const buf = Buffer.from(bytes);
    expect(CryptoWeb.enc.Hex.stringify(buf)).toBe('6869');
    expect(CryptoWeb.enc.Hex.stringify(bytes)).toBe('6869');
    expect(CryptoWeb.enc.Base64.stringify(buf)).toBe('aGk=');
    expect(CryptoWeb.enc.Base64.stringify(bytes)).toBe('aGk=');
    expect(CryptoWeb.enc.Utf8.stringify(buf)).toBe('hi');
    expect(() => CryptoWeb.enc.Utf8.stringify(bytes)).toThrow();
  });

  test('Hex.parse odd length and invalid characters', () => {
    expect(Array.from(CryptoWeb.enc.Hex.parse('abc'))).toEqual([0xab]);
    expect(Array.from(CryptoWeb.enc.Hex.parse('zz'))).toEqual([0x00]);
  });

  test('Base64.parse padding, invalid chars and newline', () => {
    expect(CryptoWeb.enc.Utf8.stringify(CryptoWeb.enc.Base64.parse('aGk'))).toBe('hi');
    expect(() => CryptoWeb.enc.Base64.parse('aGk@')).toThrow();
    expect(() => CryptoWeb.enc.Base64.parse('aGk=\naGk=')).toThrow();
  });

  test('Utf8 parse/stringify edge cases', () => {
    const nul = 'a\0b';
    const nulBytes = CryptoWeb.enc.Utf8.parse(nul);
    expect(CryptoWeb.enc.Utf8.stringify(nulBytes)).toBe(nul);

    const bad = '\uD800';
    const badBytes = CryptoWeb.enc.Utf8.parse(bad);
    expect(CryptoWeb.enc.Utf8.stringify(badBytes)).toBe('\uFFFD');

    const composed = 'e\u0301';
    const compBytes = CryptoWeb.enc.Utf8.parse(composed);
    expect(CryptoWeb.enc.Utf8.stringify(compBytes)).toBe(composed);
  });
});
