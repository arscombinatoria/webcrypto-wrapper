const CryptoWeb = require('../src');
const vectors = require('../vectors');
const { webcrypto: nodeCrypto } = require('node:crypto');

const envs = [
  ['node', () => nodeCrypto],
  ['jsdom', () => window.crypto]
];

describe.each(envs)('Hash functions in %s', (name, getCrypto) => {
  const orig = global.crypto;
  beforeAll(() => { global.crypto = getCrypto(); });
  afterAll(() => { global.crypto = orig; });

  test('hash vectors', async () => {
    const long = 'a'.repeat(1e6);
    expect((await CryptoWeb.SHA1('')).toString()).toBe(vectors.hash.sha1['']);
    expect((await CryptoWeb.SHA1('abc')).toString()).toBe(vectors.hash.sha1.abc);
    expect((await CryptoWeb.SHA1(long)).toString()).toBe(vectors.hash.sha1.long);

    expect((await CryptoWeb.SHA256('')).toString()).toBe(vectors.hash.sha256['']);
    expect((await CryptoWeb.SHA256('abc')).toString()).toBe(vectors.hash.sha256.abc);
    expect((await CryptoWeb.SHA256(long)).toString()).toBe(vectors.hash.sha256.long);

    expect((await CryptoWeb.SHA384('')).toString()).toBe(vectors.hash.sha384['']);
    expect((await CryptoWeb.SHA384('abc')).toString()).toBe(vectors.hash.sha384.abc);
    expect((await CryptoWeb.SHA384(long)).toString()).toBe(vectors.hash.sha384.long);

    expect((await CryptoWeb.SHA512('')).toString()).toBe(vectors.hash.sha512['']);
    expect((await CryptoWeb.SHA512('abc')).toString()).toBe(vectors.hash.sha512.abc);
    expect((await CryptoWeb.SHA512(long)).toString()).toBe(vectors.hash.sha512.long);

    expect((await CryptoWeb.MD5('a')).toString()).toBe(vectors.hash.md5.a);
    expect((await CryptoWeb.MD5('abc')).toString()).toBe(vectors.hash.md5.abc);
    expect((await CryptoWeb.MD5(long)).toString()).toBe(vectors.hash.md5.long);
  });
});
