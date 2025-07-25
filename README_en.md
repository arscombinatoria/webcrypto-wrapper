# WebCryptoWrapper

![coverage](./coverage/badges.svg)

WebCryptoWrapper is a lightweight wrapper that provides a consistent interface for the browser **Web Crypto API** and Node.js `crypto.webcrypto`. It aligns the invocation style and input/output with [crypto-js](https://github.com/brix/crypto-js) so that existing CryptoJS-based code can be reused with minimal changes.

When AES encryption is performed with a passphrase, it returns a CryptoJS-formatted string beginning with "Salted__". When a 16–32 byte key is specified directly, the IV is prepended to the ciphertext so that decryption can be performed from the string alone.

## Installation

```bash
npm install webcryptowrapper
```

For browsers, simply include `index.js` as a script and use `window.CryptoWeb`.

```html
<!-- example -->
<script src="./node_modules/webcryptowrapper/src/index.js"></script>
<script>
  (async () => {
    const enc = await CryptoWeb.AES.encrypt('hello', 'secret key 123');
    console.log(enc.toString());
  })();
</script>
```

## Usage

```javascript
// Node.js
const CryptoWeb = require('./index');

// Browser (after loading index.js via <script>):
// const CryptoWeb = window.CryptoWeb;

(async () => {
  // PBKDF2
  const key = await CryptoWeb.PBKDF2('password', 'salt', { keySize: 8, iterations: 1000 });

  // AES encryption (IV is automatically generated)
  const enc = await CryptoWeb.AES.encrypt('hello', key);
  console.log(enc.toString());

  // AES decryption
  const dec = await CryptoWeb.AES.decrypt(enc.toString(), key);
  console.log(dec.toString());

  // AES encryption with passphrase
  const pwEnc = await CryptoWeb.AES.encrypt('hello', 'secret key 123');
  console.log(pwEnc.toString()); // Same as CryptoJS
  const pwDec = await CryptoWeb.AES.decrypt(pwEnc.toString(), 'secret key 123');
  console.log(pwDec.toString());

  // SHA-256 and other hash functions
  const hash = await CryptoWeb.SHA256('message');
  console.log(hash.toString());
  const md5 = await CryptoWeb.MD5('message');
  console.log(md5.toString());
})();
```

## API

- `enc.Utf8`, `enc.Hex`, `enc.Base64` — CryptoJS compatible encoding utilities
- `PBKDF2(password, salt, options)` — key derivation using WebCrypto's PBKDF2
- `AES.encrypt(data, key, options)` — AES-CBC encryption
- `AES.decrypt(ciphertext, key, options)` — AES-CBC decryption
- `SHA1(data)`, `SHA256(data)`, `SHA384(data)`, `SHA512(data)` — SHA hash calculations
- `MD5(data)` — MD5 hash calculation

Each function returns a Promise and the result is a CryptoJS compatible object with a `toString()` method.

## Test

Simple tests are included in the repository. After installing dependencies, run:

```bash
npm install
npm test
```

## License

Released under the [ISC License](./LICENSE).
