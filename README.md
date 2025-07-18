# WebCryptoWrapper

crypto-js 互換の入出力を得られる簡単なラッパーです。ブラウザでは Web Crypto API、Node.js では `crypto.webcrypto.subtle` を利用します。AES 暗号化では、パスフレーズを与えた場合は CryptoJS と同じ "Salted__" 形式の文字列を返し、鍵（16〜32 バイトの値）を与えた場合は暗号文のみを返します。後者を復号する際には IV を渡す必要があります。

## 使い方

```javascript
// Node.js
const CryptoWeb = require('./index');

// Browser (after loading index.js via <script>):
// const CryptoWeb = window.CryptoWeb;

(async () => {
  // PBKDF2
  const key = await CryptoWeb.PBKDF2('password', 'salt', { keySize: 8, iterations: 1000 });

  // AES 暗号化（IVは自動生成）
  const enc = await CryptoWeb.AES.encrypt('hello', key);
  console.log(enc.toString());

  // AES 復号（IV を指定）
  const dec = await CryptoWeb.AES.decrypt(enc.toString(), key, { iv: enc.iv });
  console.log(dec.toString());

  // パスフレーズで AES 暗号化
  const pwEnc = await CryptoWeb.AES.encrypt('hello', 'secret key 123');
  console.log(pwEnc.toString()); // CryptoJS と同じ値
  const pwDec = await CryptoWeb.AES.decrypt(pwEnc.toString(), 'secret key 123');
  console.log(pwDec.toString());

  // SHA-256
  const hash = await CryptoWeb.SHA256('message');
  console.log(hash.toString());
})();
```
