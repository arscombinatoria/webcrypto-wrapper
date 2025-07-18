const assert = require('assert');
const CryptoJS = require('crypto-js');
const CryptoWeb = require('./index');

(async () => {
  try {
    // enc helpers
    const utf8Bytes = CryptoWeb.enc.Utf8.parse('hello');
    assert.strictEqual(CryptoWeb.enc.Utf8.stringify(utf8Bytes), 'hello');

    const hexStr = CryptoWeb.enc.Hex.stringify(utf8Bytes);
    assert.strictEqual(hexStr, '68656c6c6f');
    assert.strictEqual(CryptoWeb.enc.Hex.stringify(CryptoWeb.enc.Hex.parse(hexStr)), hexStr);

    const b64Str = CryptoWeb.enc.Base64.stringify(utf8Bytes);
    assert.strictEqual(b64Str, Buffer.from('hello').toString('base64'));
    assert.strictEqual(CryptoWeb.enc.Base64.stringify(CryptoWeb.enc.Base64.parse(b64Str)), b64Str);

    // SHA256
    const msg = 'Hello World';
    const hashW = await CryptoWeb.SHA256(msg);
    const hashC = CryptoJS.SHA256(msg).toString();
    assert.strictEqual(hashW.toString(), hashC);

    // PBKDF2
    const keySize = 8; // 8 words = 256 bits
    const iterations = 1000;
    const keyWrapper = await CryptoWeb.PBKDF2('password', 'salt', { keySize, iterations });
    const keyCryptoJS = CryptoJS.PBKDF2('password', 'salt', {
      keySize,
      iterations,
      hasher: CryptoJS.algo.SHA256
    }).toString();
    assert.strictEqual(keyWrapper.toString(), keyCryptoJS);

    // AES encrypt/decrypt
    const keyHex = keyWrapper.toString();
    const plaintext = 'Secret Message';
    const enc = await CryptoWeb.AES.encrypt(plaintext, keyHex);
    const dec = await CryptoWeb.AES.decrypt(enc.toString(), keyHex);
    assert.strictEqual(dec.toString(), plaintext);

    const encObj = await CryptoWeb.AES.encrypt(plaintext, keyHex);
    const decObj = await CryptoWeb.AES.decrypt(encObj, keyHex);
    assert.strictEqual(decObj.toString(), plaintext);

    console.log('All tests passed.');
  } catch (err) {
    console.error('Test failed:', err);
    process.exit(1);
  }
})();
