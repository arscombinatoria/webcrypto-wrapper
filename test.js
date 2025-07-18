const assert = require('assert');
const CryptoJS = require('crypto-js');
const CryptoWeb = require('./index');

async function runTest(name, fn) {
  try {
    await fn();
    console.log(`\u2714 ${name}`);
  } catch (err) {
    console.error(`\u2716 ${name}:`, err.message);
    throw err;
  }
}

async function runCryptoWebTests() {
  await runTest('Utf8 encode/decode', () => {
    const utf8Bytes = CryptoWeb.enc.Utf8.parse('hello');
    assert.strictEqual(CryptoWeb.enc.Utf8.stringify(utf8Bytes), 'hello');
  });

  await runTest('Hex encode/decode', () => {
    const utf8Bytes = CryptoWeb.enc.Utf8.parse('hello');
    const hexStr = CryptoWeb.enc.Hex.stringify(utf8Bytes);
    assert.strictEqual(hexStr, '68656c6c6f');
    assert.strictEqual(
      CryptoWeb.enc.Hex.stringify(CryptoWeb.enc.Hex.parse(hexStr)),
      hexStr
    );
  });

  await runTest('Base64 encode/decode', () => {
    const utf8Bytes = CryptoWeb.enc.Utf8.parse('hello');
    const b64Str = CryptoWeb.enc.Base64.stringify(utf8Bytes);
    assert.strictEqual(b64Str, Buffer.from('hello').toString('base64'));
    assert.strictEqual(
      CryptoWeb.enc.Base64.stringify(CryptoWeb.enc.Base64.parse(b64Str)),
      b64Str
    );
  });

  await runTest('SHA256 hash', async () => {
    const msg = 'Hello World';
    const hashW = await CryptoWeb.SHA256(msg);
    const hashC = CryptoJS.SHA256(msg).toString();
    assert.strictEqual(hashW.toString(), hashC);
  });

  await runTest('PBKDF2 default options', async () => {
    const keyW = await CryptoWeb.PBKDF2('password', 'salt');
    const keyC = CryptoJS.PBKDF2('password', 'salt').toString();
    assert.strictEqual(keyW.toString(), keyC);
  });

  let keyWrapper;
  await runTest('PBKDF2', async () => {
    const keySize = 8; // 8 words = 256 bits
    const iterations = 1000;
    keyWrapper = await CryptoWeb.PBKDF2('password', 'salt', {
      keySize,
      iterations
    });
    const keyCryptoJS = CryptoJS.PBKDF2('password', 'salt', {
      keySize,
      iterations,
      hasher: CryptoJS.algo.SHA256
    }).toString();
    assert.strictEqual(keyWrapper.toString(), keyCryptoJS);
  });

  await runTest('AES encrypt/decrypt string', async () => {
    const keyHex = keyWrapper.toString();
    const plaintext = 'Secret Message';
    const enc = await CryptoWeb.AES.encrypt(plaintext, keyHex);
    const dec = await CryptoWeb.AES.decrypt(enc.toString(), keyHex);
    assert.strictEqual(dec.toString(), plaintext);
  });

  await runTest('AES encrypt/decrypt object', async () => {
    const keyHex = keyWrapper.toString();
    const plaintext = 'Secret Message';
    const encObj = await CryptoWeb.AES.encrypt(plaintext, keyHex);
    const decObj = await CryptoWeb.AES.decrypt(encObj, keyHex);
    assert.strictEqual(decObj.toString(), plaintext);
  });
}

async function runCompatibilityTests() {
  const keySize = 8;
  const iterations = 1000;
  const keyHex = (
    await CryptoWeb.PBKDF2('password', 'salt', { keySize, iterations })
  ).toString();
  const plaintext = 'Secret Message';
  const ivHex = '000102030405060708090a0b0c0d0e0f';
  await runTest('CryptoWeb encrypt / CryptoJS decrypt', async () => {
    const cwEnc = await CryptoWeb.AES.encrypt(plaintext, keyHex, { iv: ivHex });
    const cwBytes = CryptoWeb.enc.Base64.parse(cwEnc.toString());
    const cwIv = cwBytes.slice(0, 16);
    const cwCt = cwBytes.slice(16);
    const cwIvWA = CryptoJS.enc.Hex.parse(CryptoWeb.enc.Hex.stringify(cwIv));
    const cwCtWA = CryptoJS.enc.Hex.parse(CryptoWeb.enc.Hex.stringify(cwCt));
    const cryptoDec = CryptoJS.AES.decrypt(
      { ciphertext: cwCtWA },
      CryptoJS.enc.Hex.parse(keyHex),
      { iv: cwIvWA }
    );
    assert.strictEqual(cryptoDec.toString(CryptoJS.enc.Utf8), plaintext);
  });

  await runTest('CryptoJS encrypt / CryptoWeb decrypt', async () => {
    const cwIvWA = CryptoJS.enc.Hex.parse(ivHex);
    const cryptoEnc = CryptoJS.AES.encrypt(
      plaintext,
      CryptoJS.enc.Hex.parse(keyHex),
      { iv: cwIvWA }
    );
    const cryptoBytes = CryptoWeb.enc.Base64.parse(cryptoEnc.toString());
    const cwIv = CryptoWeb.enc.Hex.parse(ivHex);
    const combined = new Uint8Array(cwIv.length + cryptoBytes.length);
    combined.set(cwIv);
    combined.set(cryptoBytes, cwIv.length);
    const webDec = await CryptoWeb.AES.decrypt(
      CryptoWeb.enc.Base64.stringify(combined),
      keyHex
    );
    assert.strictEqual(webDec.toString(), plaintext);
  });
}

(async () => {
  try {
    await runCryptoWebTests();
    await runCompatibilityTests();
    console.log('All tests passed.');
  } catch (err) {
    console.error('Test failed:', err);
    process.exit(1);
  }
})();
