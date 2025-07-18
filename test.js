const CryptoJS = require('crypto-js');
const CryptoWeb = require('./index');

(async () => {
  // Test sha256
  const msg = 'Hello World';
  const hashW = await CryptoWeb.SHA256(msg);
  console.log('sha256 wrapper:', hashW.toString());
  console.log('sha256 cryptojs:', CryptoJS.SHA256(msg).toString());

  // Test pbkdf2
  const keySize = 8; // 8 words = 256 bits
  const iter = 1000;
  const keyWrapper = await CryptoWeb.PBKDF2('password', 'salt', { keySize, iterations: iter });
  const keyCryptoJS = CryptoJS.PBKDF2('password', 'salt', {
    keySize,
    iterations: iter,
    hasher: CryptoJS.algo.SHA256
  }).toString();
  console.log('pbkdf2 wrapper:', keyWrapper.toString());
  console.log('pbkdf2 cryptojs:', keyCryptoJS);

  // AES
  const keyHex = keyWrapper.toString();
  const plaintext = 'Secret Message';
  const enc = await CryptoWeb.AES.encrypt(plaintext, keyHex);
  console.log('aes encrypt wrapper:', enc.toString());
  const dec = await CryptoWeb.AES.decrypt(enc.toString(), keyHex);
  console.log('aes decrypt wrapper:', dec.toString());
})();
