/**
 * WebCryptoWrapper
 *
 * A small wrapper around the Web Crypto API and Node.js crypto module.
 * Provides CryptoJS compatible helpers for encoding, PBKDF2, AES-CBC and
 * SHA-1/256/384/512 hash operations.
 * @namespace CryptoWeb
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CryptoWeb = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  const globalObj = typeof self !== 'undefined' ? self : this;
  let nodeCrypto;
  try { nodeCrypto = typeof require === 'function' ? require('node:crypto') : undefined; }
  catch (e) { try { nodeCrypto = require('crypto'); } catch (err) { nodeCrypto = undefined; } }
  const webcrypto = (globalObj.crypto && globalObj.crypto.subtle) ? globalObj.crypto
    : (nodeCrypto && nodeCrypto.webcrypto);
  if (!webcrypto || !webcrypto.subtle) {
    throw new Error('WebCrypto not available');
  }
  const subtle = webcrypto.subtle;

  /**
   * Generate cryptographically secure random bytes.
   *
   * @param {number} len - Number of bytes to generate.
   * @returns {Uint8Array} Random bytes.
   */
  function getRandomBytes(len) {
    if (webcrypto.getRandomValues) {
      return webcrypto.getRandomValues(new Uint8Array(len));
    }
    if (nodeCrypto && nodeCrypto.randomBytes) {
      return new Uint8Array(nodeCrypto.randomBytes(len));
    }
    throw new Error('No secure random generator');
  }

  /* enc helpers ---------------------------------------------------------- */
  /**
   * Encoding helper functions equivalent to `CryptoJS.enc.*` namespaces.
   * @namespace
   */
  const enc = {
    Utf8: {
      parse: (str) => new TextEncoder().encode(str),
      stringify: (bytes) => new TextDecoder().decode(bytes)
    },
    Hex: {
      parse: (hex) => Uint8Array.from(hex.match(/.{2}/g).map(b => parseInt(b, 16))),
      stringify: (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    },
    Base64: {
      parse: (b64) => {
        if (typeof atob === 'function') {
          return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        }
        return new Uint8Array(Buffer.from(b64, 'base64'));
      },
      stringify: (bytes) => {
        if (typeof btoa === 'function') {
          return btoa(String.fromCharCode(...bytes));
        }
        return Buffer.from(bytes).toString('base64');
      }
    }
  };

  /**
   * Create a CryptoJS compatible word array object from bytes.
   * @param {Uint8Array} bytes - Input bytes.
   * @param {Object} [encoder=enc.Hex] - Default encoder for toString().
   * @returns {{words: Uint8Array, sigBytes: number, toString: function}}
   */
  function wa(bytes, encoder = enc.Hex) {
    return {
      words: bytes,
      sigBytes: bytes.length,
      toString(fmt = encoder) { return fmt.stringify(bytes); }
    };
  }

  /* PBKDF2 --------------------------------------------------------------- */
  /**
   * Derive a key using PBKDF2.
   *
   * @param {string|Uint8Array} password - Password or byte array.
   * @param {string|Uint8Array} salt - Salt value.
   * @param {Object} [cfg] - Configuration options.
   * @param {number} [cfg.iterations=1000] - Number of iterations.
   * @param {number} [cfg.keySize=8] - Desired key size in words (32-bit units).
   * @param {string} [cfg.hash='SHA-256'] - Hash algorithm name.
   * @returns {Promise<{words: Uint8Array, sigBytes: number, toString: function}>}
   *   Promise resolving to a CryptoJS compatible word array object.
   */
  async function PBKDF2(password, salt, cfg = {}) {
    const { iterations = 250000, keySize = 128 / 32, hash = 'SHA-256' } = cfg;
    const passBytes = typeof password === 'string' ? enc.Utf8.parse(password) : password;
    const saltBytes = typeof salt === 'string' ? enc.Utf8.parse(salt) : salt;
    const baseKey = await subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations, hash }, baseKey, keySize * 32);
    const bytes = new Uint8Array(bits);
    return wa(bytes, enc.Hex);
  }

  /**
   * Compute MD5 digest of the given data.
   * Used internally for OpenSSL style key derivation.
   *
   * @private
   * @param {Uint8Array} bytes - Input bytes.
   * @returns {Uint8Array} The MD5 hash as bytes.
   */
  function md5(bytes) {
    if (nodeCrypto && nodeCrypto.createHash) {
      return new Uint8Array(nodeCrypto.createHash('md5').update(Buffer.from(bytes)).digest());
    }
    const s = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
               5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
               4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
               6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    const K = [];
    for (let i = 0; i < 64; i++) {
      K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
    }
    const len = bytes.length;
    const bitLen = len * 8;
    const withPadding = (((len + 8) >>> 6) + 1) * 64;
    const buf = new Uint8Array(withPadding);
    buf.set(bytes);
    buf[len] = 0x80;
    for (let i = 0; i < 8; i++) buf[withPadding - 8 + i] = (bitLen >>> (8 * i)) & 0xff;
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const view = new DataView(buf.buffer);
    for (let i = 0; i < withPadding; i += 64) {
      let A = a0, B = b0, C = c0, D = d0;
      for (let j = 0; j < 64; j++) {
        let F, g;
        if (j < 16) { F = (B & C) | (~B & D); g = j; }
        else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
        else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * j) % 16; }
        const tmp = D;
        D = C;
        C = B;
        F = (F + A + K[j] + view.getUint32(i + g * 4, true)) >>> 0;
        B = (B + ((F << s[j]) | (F >>> (32 - s[j])))) >>> 0;
        A = tmp;
      }
      a0 = (a0 + A) >>> 0;
      b0 = (b0 + B) >>> 0;
      c0 = (c0 + C) >>> 0;
      d0 = (d0 + D) >>> 0;
    }
    const out = new Uint8Array(16);
    new DataView(out.buffer).setUint32(0, a0, true);
    new DataView(out.buffer).setUint32(4, b0, true);
    new DataView(out.buffer).setUint32(8, c0, true);
    new DataView(out.buffer).setUint32(12, d0, true);
    return out;
  }

  /**
   * Derive key and IV using an OpenSSL-compatible EVP algorithm.
   *
   * @private
   * @param {Uint8Array} passBytes - Password bytes.
   * @param {Uint8Array} saltBytes - Salt bytes.
   * @param {number} [keySize=32] - Length of the derived key in bytes.
   * @param {number} [ivSize=16] - Length of the derived IV in bytes.
   * @returns {{key: Uint8Array, iv: Uint8Array}} Derived key and IV.
   */
  function evpKDF(passBytes, saltBytes, keySize = 32, ivSize = 16) {
    const total = keySize + ivSize;
    let derived = new Uint8Array(0);
    let block = new Uint8Array(0);
    while (derived.length < total) {
      const data = new Uint8Array(block.length + passBytes.length + saltBytes.length);
      data.set(block);
      data.set(passBytes, block.length);
      data.set(saltBytes, block.length + passBytes.length);
      block = md5(data);
      const temp = new Uint8Array(derived.length + block.length);
      temp.set(derived);
      temp.set(block, derived.length);
      derived = temp;
    }
    return { key: derived.slice(0, keySize), iv: derived.slice(keySize, total) };
  }

  /* AES ------------------------------------------------------------------ */
  /**
   * AES-CBC encryption and decryption helpers.
   * @namespace
   */
  const AES = {
    /**
     * Encrypt data using AES-CBC.
     *
     * @param {string|Uint8Array} plaintext - Data to encrypt.
     * @param {string|Uint8Array|Object} key - Hex string, key bytes or PBKDF2 output.
     * @param {Object} [cfg] - Optional configuration.
     * @param {string|Uint8Array} [cfg.iv] - Initialization vector. Randomly generated if omitted.
     * @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array, toString: function}>}
     *   Promise resolving to an object containing IV and ciphertext.
     */
    encrypt: async function (plaintext, key, cfg = {}) {
      const ptBytes = typeof plaintext === 'string' ? enc.Utf8.parse(plaintext) : plaintext;
      let keyBytes, ivBytes, saltBytes, passphrase = false;
      if (typeof key === 'string' && (!/^[0-9a-fA-F]+$/.test(key) || ![32,48,64].includes(key.length))) {
        passphrase = true;
        saltBytes = cfg.salt ? (typeof cfg.salt === 'string' ? enc.Hex.parse(cfg.salt) : cfg.salt) : getRandomBytes(8);
        const derived = evpKDF(enc.Utf8.parse(key), saltBytes);
        keyBytes = derived.key;
        ivBytes = derived.iv;
      } else {
        if (typeof key === 'string') keyBytes = enc.Hex.parse(key);
        else if (key && key.words) keyBytes = key.words;
        else keyBytes = key;
        if (![16, 24, 32].includes(keyBytes.length)) throw new Error('Key length must be 128/192/256 bits');
        if (cfg.iv) ivBytes = typeof cfg.iv === 'string' ? enc.Hex.parse(cfg.iv) : cfg.iv;
        else ivBytes = getRandomBytes(16);
      }
      const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-CBC', length: keyBytes.length * 8 }, false, ['encrypt']);
      const cipherBuf = await subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, cryptoKey, ptBytes);
      const cipherBytes = new Uint8Array(cipherBuf);
      return {
        iv: wa(ivBytes, enc.Hex),
        salt: saltBytes && wa(saltBytes, enc.Hex),
        ciphertext: wa(cipherBytes, enc.Hex),
        toString(encoder = enc.Base64) {
          if (passphrase) {
            const prefix = enc.Utf8.parse('Salted__');
            const all = new Uint8Array(prefix.length + saltBytes.length + cipherBytes.length);
            all.set(prefix);
            all.set(saltBytes, prefix.length);
            all.set(cipherBytes, prefix.length + saltBytes.length);
            return encoder.stringify(all);
          }
          const all = new Uint8Array(ivBytes.length + cipherBytes.length);
          all.set(ivBytes);
          all.set(cipherBytes, ivBytes.length);
          return encoder.stringify(all);
        }
      };
    },

    /**
     * Decrypt data that was encrypted with AES-CBC.
     *
     * @param {string|Uint8Array|Object} ciphertext - Base64 string, byte array or
     *     object containing `ciphertext` and `iv`.
     * @param {string|Uint8Array|Object} key - Hex string, key bytes or PBKDF2 output.
     * @param {Object} [cfg] - Optional configuration.
     * @param {string|Uint8Array} [cfg.iv] - Initialization vector, overrides embedded IV.
     * @returns {Promise<{words: Uint8Array, sigBytes: number, toString: function}>}
     *   Promise resolving to a CryptoJS compatible plaintext object.
     */
    decrypt: async function (ciphertext, key, cfg = {}) {
      let ctBytes, ivBytes, saltBytes, passphrase = false, keyBytes;
      if (typeof ciphertext === 'string') {
        const all = enc.Base64.parse(ciphertext);
        if (all.length >= 16 && enc.Utf8.stringify(all.slice(0, 8)) === 'Salted__') {
          saltBytes = all.slice(8, 16);
          ctBytes = all.slice(16);
        } else if (all.length > 16) {
          ivBytes = all.slice(0, 16);
          ctBytes = all.slice(16);
        } else {
          ctBytes = all;
        }
      } else if (ciphertext && ciphertext.ciphertext) {
        ivBytes = ciphertext.iv && (ciphertext.iv.words || ciphertext.iv);
        ctBytes = ciphertext.ciphertext.words || ciphertext.ciphertext;
        saltBytes = ciphertext.salt && (ciphertext.salt.words || ciphertext.salt);
      } else if (ciphertext && ciphertext.length) {
        ctBytes = ciphertext;
      } else {
        throw new Error('invalid ciphertext');
      }

      if (typeof key === 'string' && (!/^[0-9a-fA-F]+$/.test(key) || ![32,48,64].includes(key.length) || saltBytes)) {
        passphrase = true;
        if (!saltBytes) {
          if (!cfg.salt) throw new Error('salt required');
          saltBytes = typeof cfg.salt === 'string' ? enc.Hex.parse(cfg.salt) : cfg.salt;
        }
        const derived = evpKDF(enc.Utf8.parse(key), saltBytes);
        keyBytes = derived.key;
        ivBytes = derived.iv;
      } else {
        if (typeof key === 'string') keyBytes = enc.Hex.parse(key);
        else if (key && key.words) keyBytes = key.words;
        else keyBytes = key;
        if (cfg.iv) ivBytes = typeof cfg.iv === 'string' ? enc.Hex.parse(cfg.iv) : cfg.iv;
      }
      if (!ivBytes) throw new Error('IV required');
      const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-CBC', length: keyBytes.length * 8 }, false, ['decrypt']);
      const plainBuf = await subtle.decrypt({ name: 'AES-CBC', iv: ivBytes }, cryptoKey, ctBytes);
      const plainBytes = new Uint8Array(plainBuf);
      return {
        words: plainBytes,
        sigBytes: plainBytes.length,
        toString(encoder = enc.Utf8) { return encoder.stringify(plainBytes); }
      };
    }
  };

  /* SHA hashes ----------------------------------------------------------- */
  /**
   * Compute SHA-1 digest of data.
   * @param {string|Uint8Array} data - Data to hash.
   * @returns {Promise<{words: Uint8Array, sigBytes: number, toString: function}>}
   *   Promise resolving to a CryptoJS compatible hash object.
   */
  async function SHA1(data) {
    const bytes = typeof data === 'string' ? enc.Utf8.parse(data) : data;
    const digest = await subtle.digest('SHA-1', bytes);
    const res = new Uint8Array(digest);
    return {
      words: res,
      sigBytes: res.length,
      toString(encoder = enc.Hex) { return encoder.stringify(res); }
    };
  }

  /**
   * Compute SHA-256 digest of data.
   * @param {string|Uint8Array} data - Data to hash.
   * @returns {Promise<{words: Uint8Array, sigBytes: number, toString: function}>}
   *   Promise resolving to a CryptoJS compatible hash object.
   */
  async function SHA256(data) {
    const bytes = typeof data === 'string' ? enc.Utf8.parse(data) : data;
    const digest = await subtle.digest('SHA-256', bytes);
    const res = new Uint8Array(digest);
    return {
      words: res,
      sigBytes: res.length,
      toString(encoder = enc.Hex) { return encoder.stringify(res); }
    };
  }

  /**
   * Compute SHA-384 digest of data.
   * @param {string|Uint8Array} data - Data to hash.
   * @returns {Promise<{words: Uint8Array, sigBytes: number, toString: function}>}
   *   Promise resolving to a CryptoJS compatible hash object.
   */
  async function SHA384(data) {
    const bytes = typeof data === 'string' ? enc.Utf8.parse(data) : data;
    const digest = await subtle.digest('SHA-384', bytes);
    const res = new Uint8Array(digest);
    return {
      words: res,
      sigBytes: res.length,
      toString(encoder = enc.Hex) { return encoder.stringify(res); }
    };
  }

  /**
   * Compute SHA-512 digest of data.
   * @param {string|Uint8Array} data - Data to hash.
   * @returns {Promise<{words: Uint8Array, sigBytes: number, toString: function}>}
   *   Promise resolving to a CryptoJS compatible hash object.
   */
  async function SHA512(data) {
    const bytes = typeof data === 'string' ? enc.Utf8.parse(data) : data;
    const digest = await subtle.digest('SHA-512', bytes);
    const res = new Uint8Array(digest);
    return {
      words: res,
      sigBytes: res.length,
      toString(encoder = enc.Hex) { return encoder.stringify(res); }
    };
  }

  /**
   * Compute MD5 digest of data.
   * @param {string|Uint8Array} data - Data to hash.
   * @returns {Promise<{words: Uint8Array, sigBytes: number, toString: function}>}
   *   Promise resolving to a CryptoJS compatible hash object.
   */
  async function MD5(data) {
    const bytes = typeof data === 'string' ? enc.Utf8.parse(data) : data;
    let res;
    if (nodeCrypto && nodeCrypto.createHash) {
      res = new Uint8Array(nodeCrypto.createHash('md5').update(Buffer.from(bytes)).digest());
    } else {
      res = md5(bytes);
    }
    return {
      words: res,
      sigBytes: res.length,
      toString(encoder = enc.Hex) { return encoder.stringify(res); }
    };
  }

  /**
   * Exposed API providing encoding utilities and cryptographic functions.
   * @type {{enc: object, PBKDF2: Function, AES: object,
   *         MD5: Function,
   *         SHA1: Function, SHA256: Function, SHA384: Function, SHA512: Function}}
   */
  return { enc, wa, PBKDF2, AES, MD5, SHA1, SHA256, SHA384, SHA512 };
}));
