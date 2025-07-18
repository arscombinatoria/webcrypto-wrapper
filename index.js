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

  /* PBKDF2 --------------------------------------------------------------- */
  async function PBKDF2(password, salt, cfg = {}) {
    const { iterations = 250000, keySize = 128 / 32, hash = 'SHA-256' } = cfg;
    const passBytes = typeof password === 'string' ? enc.Utf8.parse(password) : password;
    const saltBytes = typeof salt === 'string' ? enc.Utf8.parse(salt) : salt;
    const baseKey = await subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations, hash }, baseKey, keySize * 32);
    const bytes = new Uint8Array(bits);
    return {
      words: bytes,
      sigBytes: bytes.length,
      toString(encoder = enc.Hex) { return encoder.stringify(bytes); }
    };
  }

  /* AES ------------------------------------------------------------------ */
  const AES = {
    encrypt: async function (plaintext, key, cfg = {}) {
      const ptBytes = typeof plaintext === 'string' ? enc.Utf8.parse(plaintext) : plaintext;
      let keyBytes;
      if (typeof key === 'string') keyBytes = enc.Hex.parse(key);
      else if (key && key.words) keyBytes = key.words;
      else keyBytes = key;
      if (![16, 24, 32].includes(keyBytes.length)) throw new Error('Key length must be 128/192/256 bits');
      const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-CBC', length: keyBytes.length * 8 }, false, ['encrypt']);
      let ivBytes;
      if (cfg.iv) ivBytes = typeof cfg.iv === 'string' ? enc.Hex.parse(cfg.iv) : cfg.iv;
      else ivBytes = getRandomBytes(16);
      const cipherBuf = await subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, cryptoKey, ptBytes);
      const cipherBytes = new Uint8Array(cipherBuf);
      const combined = new Uint8Array(ivBytes.length + cipherBytes.length);
      combined.set(ivBytes);
      combined.set(cipherBytes, ivBytes.length);
      return {
        iv: ivBytes,
        ciphertext: cipherBytes,
        toString(encoder = enc.Base64) { return encoder.stringify(combined); }
      };
    },

    decrypt: async function (ciphertext, key, cfg = {}) {
      let ctBytes, ivBytes;
      if (typeof ciphertext === 'string') {
        const all = enc.Base64.parse(ciphertext);
        if (all.length < 17) throw new Error('ciphertext too short');
        ivBytes = all.slice(0, 16);
        ctBytes = all.slice(16);
      } else if (ciphertext && ciphertext.ciphertext) {
        ivBytes = ciphertext.iv;
        ctBytes = ciphertext.ciphertext;
      } else if (ciphertext && ciphertext.length) {
        ctBytes = ciphertext;
      } else {
        throw new Error('invalid ciphertext');
      }
      if (cfg.iv) ivBytes = typeof cfg.iv === 'string' ? enc.Hex.parse(cfg.iv) : cfg.iv;
      if (!ivBytes) throw new Error('IV required');
      let keyBytes;
      if (typeof key === 'string') keyBytes = enc.Hex.parse(key);
      else if (key && key.words) keyBytes = key.words;
      else keyBytes = key;
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

  /* SHA-256 -------------------------------------------------------------- */
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

  return { enc, PBKDF2, AES, SHA256 };
}));
