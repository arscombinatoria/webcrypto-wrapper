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

  test('Hex.parse odd length and invalid chars', () => {
    expect(Array.from(CryptoWeb.enc.Hex.parse('abc')))
      .toEqual(Array.from(CryptoWeb.enc.Hex.parse('ab')));
    expect(Array.from(CryptoWeb.enc.Hex.parse('gh'))).toEqual([0]);
  });

  test('Base64.parse edge cases', () => {
    const noPad = CryptoWeb.enc.Base64.parse('aGk');
    expect(CryptoWeb.enc.Utf8.stringify(noPad)).toBe('hi');
    expect(() => CryptoWeb.enc.Base64.parse('aGk=\naGk=')).toThrow();
    expect(() => CryptoWeb.enc.Base64.parse('??')).toThrow();
  });

  test('Utf8 special strings', () => {
    const nul = CryptoWeb.enc.Utf8.parse('a\0b');
    expect(nul[1]).toBe(0);
    expect(CryptoWeb.enc.Utf8.stringify(nul)).toBe('a\0b');

    const invalid = CryptoWeb.enc.Utf8.parse('\uD800');
    expect(CryptoWeb.enc.Utf8.stringify(invalid)).toBe('\uFFFD');

    const composite = 'A\u030A';
    const round = CryptoWeb.enc.Utf8.stringify(CryptoWeb.enc.Utf8.parse(composite));
    expect(round).toBe(composite);
  });
});
