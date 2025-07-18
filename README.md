# WebCryptoWrapper

crypto-js 互換の入出力を得られる簡単なラッパーです。ブラウザでは Web Crypto API、Node.js では `crypto.webcrypto.subtle` を利用します。IV を暗号文の先頭に連結するため、CryptoJS と同様に文字列だけで復号できます。

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

  // AES 復号
  const dec = await CryptoWeb.AES.decrypt(enc.toString(), key);
  console.log(dec.toString());

  // SHA-256
  const hash = await CryptoWeb.SHA256('message');
  console.log(hash.toString());
})();
```
