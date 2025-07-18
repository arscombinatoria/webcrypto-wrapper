// このスクリプトでは CryptoWeb ラッパーの動作を確認するテストを実行します。
const assert = require('assert');
const CryptoJS = require('crypto-js');
// index.js で公開されているモジュールを読み込む
const CryptoWeb = require('./index');

// 個々のテストを実行し、結果を表示するユーティリティ関数
async function runTest(name, fn) {
  try {
    await fn();
    console.log(`\u2714 ${name}`);
  } catch (err) {
    console.error(`\u2716 ${name}:`, err.message);
    throw err;
  }
}

// CryptoWeb 単体の機能が期待通り動作するか確認するテスト群
async function runCryptoWebTests() {
  // UTF-8 エンコード・デコードのテスト
  await runTest('Utf8 encode/decode', () => {
    const utf8Bytes = CryptoWeb.enc.Utf8.parse('hello');
    assert.strictEqual(CryptoWeb.enc.Utf8.stringify(utf8Bytes), 'hello');
  });

  // 16進表現でのエンコード・デコードのテスト
  await runTest('Hex encode/decode', () => {
    const utf8Bytes = CryptoWeb.enc.Utf8.parse('hello');
    const hexStr = CryptoWeb.enc.Hex.stringify(utf8Bytes);
    assert.strictEqual(hexStr, '68656c6c6f');
    assert.strictEqual(
      CryptoWeb.enc.Hex.stringify(CryptoWeb.enc.Hex.parse(hexStr)),
      hexStr
    );
  });

  // Base64 エンコード・デコードのテスト
  await runTest('Base64 encode/decode', () => {
    const utf8Bytes = CryptoWeb.enc.Utf8.parse('hello');
    const b64Str = CryptoWeb.enc.Base64.stringify(utf8Bytes);
    assert.strictEqual(b64Str, Buffer.from('hello').toString('base64'));
    assert.strictEqual(
      CryptoWeb.enc.Base64.stringify(CryptoWeb.enc.Base64.parse(b64Str)),
      b64Str
    );
  });

  // SHA256 ハッシュの計算が CryptoJS と一致するか
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
  // PBKDF2 で生成した鍵が CryptoJS と同じになるか
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

  // 文字列を AES で暗号化・復号するテスト
  await runTest('AES encrypt/decrypt string', async () => {
    const keyHex = keyWrapper.toString();
    const plaintext = 'Secret Message';
    const enc = await CryptoWeb.AES.encrypt(plaintext, keyHex);
    const dec = await CryptoWeb.AES.decrypt(enc.toString(), keyHex, { iv: enc.iv });
    assert.strictEqual(dec.toString(), plaintext);
  });

  // 暗号化結果のオブジェクトを直接復号するテスト
  await runTest('AES encrypt/decrypt object', async () => {
    const keyHex = keyWrapper.toString();
    const plaintext = 'Secret Message';
    const encObj = await CryptoWeb.AES.encrypt(plaintext, keyHex);
    const decObj = await CryptoWeb.AES.decrypt(encObj, keyHex);
    assert.strictEqual(decObj.toString(), plaintext);
  });

  // パスフレーズで暗号化・復号できるか
  await runTest('AES passphrase encrypt/decrypt', async () => {
    const plaintext = 'Secret Message';
    const saltWA = CryptoJS.lib.WordArray.random(8);
    const saltHex = saltWA.toString();
    const encObj = await CryptoWeb.AES.encrypt(plaintext, 'secret key 123', { salt: saltHex });
    const decObj = await CryptoWeb.AES.decrypt(encObj.toString(), 'secret key 123');
    assert.strictEqual(decObj.toString(), plaintext);
    const cryptoEnc = CryptoJS.AES.encrypt(plaintext, 'secret key 123', { salt: saltWA });
    assert.strictEqual(encObj.toString(), cryptoEnc.toString());
  });
}

// CryptoWeb と CryptoJS で相互に暗号化・復号できるかを確認する互換性テスト
async function runCompatibilityTests() {
  const keySize = 8;
  const iterations = 1000;
  const keyHex = (
    await CryptoWeb.PBKDF2('password', 'salt', { keySize, iterations })
  ).toString();
  const plaintext = 'Secret Message';
  const ivHex = '000102030405060708090a0b0c0d0e0f';
  // CryptoWeb で暗号化し、CryptoJS で復号できるか
  await runTest('CryptoWeb encrypt / CryptoJS decrypt', async () => {
    const cwEnc = await CryptoWeb.AES.encrypt(plaintext, keyHex, { iv: ivHex });
    const cwIvWA = CryptoJS.enc.Hex.parse(CryptoWeb.enc.Hex.stringify(cwEnc.iv));
    const cwCtWA = CryptoJS.enc.Hex.parse(CryptoWeb.enc.Hex.stringify(cwEnc.ciphertext));
    const cryptoDec = CryptoJS.AES.decrypt(
      { ciphertext: cwCtWA },
      CryptoJS.enc.Hex.parse(keyHex),
      { iv: cwIvWA }
    );
    assert.strictEqual(cryptoDec.toString(CryptoJS.enc.Utf8), plaintext);
  });

  // CryptoJS で暗号化したものを CryptoWeb で復号できるか
  await runTest('CryptoJS encrypt / CryptoWeb decrypt', async () => {
    const cwIvWA = CryptoJS.enc.Hex.parse(ivHex);
    const cryptoEnc = CryptoJS.AES.encrypt(
      plaintext,
      CryptoJS.enc.Hex.parse(keyHex),
      { iv: cwIvWA }
    );
    const webDec = await CryptoWeb.AES.decrypt(
      cryptoEnc.toString(),
      keyHex,
      { iv: ivHex }
    );
    assert.strictEqual(webDec.toString(), plaintext);
  });

  await runTest('Passphrase compatibility', async () => {
    const saltWA = CryptoJS.lib.WordArray.random(8);
    const saltHex = saltWA.toString();
    const cryptoEnc = CryptoJS.AES.encrypt(plaintext, 'secret key 123', { salt: saltWA });
    const webEnc = await CryptoWeb.AES.encrypt(plaintext, 'secret key 123', { salt: saltHex });
    assert.strictEqual(webEnc.toString(), cryptoEnc.toString());
    const webDec = await CryptoWeb.AES.decrypt(cryptoEnc.toString(), 'secret key 123');
    assert.strictEqual(webDec.toString(), plaintext);
    const cryptoDec = CryptoJS.AES.decrypt(webEnc.toString(), 'secret key 123');
    assert.strictEqual(cryptoDec.toString(CryptoJS.enc.Utf8), plaintext);
  });
}

// スクリプトを直接実行したときにテストを順番に実行する
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
