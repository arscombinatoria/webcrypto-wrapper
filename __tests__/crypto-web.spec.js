const CryptoWeb = require('../src');
const CryptoJS = require('crypto-js');
const { webcrypto: nodeCrypto } = require('node:crypto');

const vectors = {
  aesCbc: [
    {
      key: '2b7e151628aed2a6abf7158809cf4f3c',
      iv: '000102030405060708090a0b0c0d0e0f',
      pt: '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
      ct: '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7'
    },
    {
      key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
      iv: '000102030405060708090a0b0c0d0e0f',
      pt: '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
      ct: '4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd'
    },
    {
      key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
      iv: '000102030405060708090a0b0c0d0e0f',
      pt: '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
      ct: 'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b'
    }
  ],
  evp: {
    salt: '0001020304050607',
    iv: '1D112C3C48B1D30DBCEEAFF080816BE4',
    cipher: 'U2FsdGVkX18AAQIDBAUGB8TniaJDjKzdd85nJ/Zhn2Q='
  },
  pbkdf2: {
    password: 'password',
    salt: 'salt',
    iters: {
      1000: '632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3',
      2000: '9209a0c90243e88b89488f99cd7ea010c244cc7a9d4bf65c157f2d8f642eb952',
      4000: '99a4d4dd66f714fae1bab9246ea449dd598d7683a569227c07cdb679e3ed3474',
      40000:'6fe82165126e491e8099ea9519f4cd9a201860487ffbf4037a5060ec5ecdf334'
    }
  },
  hash: {
    sha1: {
      '': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      abc: 'a9993e364706816aba3e25717850c26c9cd0d89d',
      long: '34aa973cd4c4daa4f61eeb2bdbad27316534016f'
    },
    sha256: {
      '': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      abc: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      long: 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'
    },
    sha384: {
      '': '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
      abc: 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
      long: '9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985'
    },
    sha512: {
      '': 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
      abc: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
      long: 'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b'
    },
    md5: {
      a: '0cc175b9c0f1b6a831c399e269772661',
      abc: '900150983cd24fb0d6963f7d28e17f72',
      long: '7707d6ae4e027c70eea2a935c2296f21'
    }
  }
};

const envs = [
  ['node', () => nodeCrypto],
  ['jsdom', () => window.crypto]
];

describe.each(envs)('CryptoWeb in %s', (name, getCrypto) => {
  const origCrypto = global.crypto;

  beforeAll(() => {
    global.crypto = getCrypto();
    jest.spyOn(global.crypto, 'getRandomValues').mockImplementation(arr => {
      arr.set(Uint8Array.from({ length: arr.length }, (_, i) => i + 1));
      return arr;
    });
  });

  afterAll(() => {
    global.crypto = origCrypto;
    jest.restoreAllMocks();
  });

  test('encoding helpers', () => {
    const msg = 'hello';
    const utf8 = CryptoWeb.enc.Utf8.parse(msg);
    const hex = CryptoWeb.enc.Hex.stringify(utf8);
    const b64 = CryptoWeb.enc.Base64.stringify(utf8);
    expect(CryptoWeb.enc.Utf8.stringify(utf8)).toBe(msg);
    expect(CryptoWeb.enc.Hex.stringify(CryptoWeb.enc.Hex.parse(hex))).toBe(hex);
    expect(CryptoWeb.enc.Base64.stringify(CryptoWeb.enc.Base64.parse(b64))).toBe(b64);
  });

  test('AES NIST vectors', async () => {
    for (const v of vectors.aesCbc) {
      const pt = CryptoWeb.enc.Hex.parse(v.pt);
      const r = await CryptoWeb.AES.encrypt(pt, v.key, { iv: v.iv });
      const hex = CryptoWeb.enc.Hex.stringify(r.ciphertext);
      expect(hex.slice(0, v.ct.length)).toBe(v.ct);
      const dec = await CryptoWeb.AES.decrypt(r, v.key);
      expect(CryptoWeb.enc.Hex.stringify(dec.words)).toBe(v.pt);
    }
  });

  test('EVP_BytesToKey compatibility', async () => {
    const enc = await CryptoWeb.AES.encrypt('Hello', 'secret', { salt: vectors.evp.salt });
    expect(CryptoWeb.enc.Hex.stringify(enc.iv).toUpperCase()).toBe(vectors.evp.iv);
    expect(enc.toString()).toBe(vectors.evp.cipher);
    const dec = await CryptoWeb.AES.decrypt(enc.toString(), 'secret');
    expect(dec.toString()).toBe('Hello');
  });

  test('AES invalid parameters', async () => {
    await expect(CryptoWeb.AES.encrypt('x', new Uint8Array(5))).rejects.toThrow('Key length');
    await expect(CryptoWeb.AES.decrypt('abcd', 'deadbeef')).rejects.toThrow('salt required');
    const keyHex = '00112233445566778899aabbccddeeff';
    await expect(CryptoWeb.AES.decrypt('abcd', keyHex)).rejects.toThrow('IV required');
    await expect(CryptoWeb.AES.decrypt({ ciphertext: new Uint8Array([1,2,3]) }, keyHex)).rejects.toThrow('IV required');
    await expect(CryptoWeb.AES.decrypt(null, keyHex)).rejects.toThrow('invalid ciphertext');
  });

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

  test('CryptoWeb <-> CryptoJS', async () => {
    const keyHex = (await CryptoWeb.PBKDF2('password', 'salt', {
      keySize: 256 / 32,
      iterations: 1000
    })).toString();
    const ivHex = '000102030405060708090a0b0c0d0e0f';

    const cwEnc = await CryptoWeb.AES.encrypt('secret', keyHex, { iv: ivHex });
    const cwCtWA = CryptoJS.enc.Hex.parse(CryptoWeb.enc.Hex.stringify(cwEnc.ciphertext));
    const cwIvWA = CryptoJS.enc.Hex.parse(CryptoWeb.enc.Hex.stringify(cwEnc.iv));
    const cjDec = CryptoJS.AES.decrypt({ ciphertext: cwCtWA }, CryptoJS.enc.Hex.parse(keyHex), { iv: cwIvWA });
    expect(cjDec.toString(CryptoJS.enc.Utf8)).toBe('secret');

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
