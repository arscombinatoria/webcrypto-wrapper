const Benchmark = require('benchmark');
const CryptoWeb = require('../src');
const CryptoJS = require('crypto-js');
const fs = require('fs');

const suite = new Benchmark.Suite();
const results = [];
const data = 'benchmark data';
const password = 'password';
const salt = 'salt';

function addBench(name, cwFn, cjFn) {
  suite.add('CryptoWeb ' + name, {
    defer: true,
    maxTime: 0.5,
    minSamples: 20,
    fn: async deferred => { await cwFn(); deferred.resolve(); }
  });
  if (cjFn) {
    suite.add('CryptoJS ' + name, {
      defer: true,
      maxTime: 0.5,
      minSamples: 20,
      fn: async deferred => { await cjFn(); deferred.resolve(); }
    });
  }
}

function targetList() {
  const targets = [];
  for (const [name, val] of Object.entries(CryptoWeb)) {
    if (name === 'AES') {
      const keyHex = '00112233445566778899aabbccddeeff';
      const ivHex  = '00000000000000000000000000000000';
      targets.push(['AES.encrypt', () => CryptoWeb.AES.encrypt(data, keyHex, { iv: ivHex }),
                                    () => Promise.resolve(CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(keyHex), { iv: CryptoJS.enc.Hex.parse(ivHex) }))]);
      targets.push(['AES.decrypt', async () => {
        const enc = await CryptoWeb.AES.encrypt(data, keyHex, { iv: ivHex });
        return CryptoWeb.AES.decrypt(enc, keyHex, { iv: ivHex });
      }, () => {
        const ct = CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(keyHex), { iv: CryptoJS.enc.Hex.parse(ivHex) });
        return Promise.resolve(CryptoJS.AES.decrypt(ct, CryptoJS.enc.Hex.parse(keyHex), { iv: CryptoJS.enc.Hex.parse(ivHex) }));
      }]);
    } else if (typeof val === 'function' && ['PBKDF2','SHA1','SHA256','SHA384','SHA512','MD5'].includes(name)) {
      const cjName = name === 'PBKDF2' ? 'PBKDF2' : name;
      if (name === 'PBKDF2') {
        targets.push([name, () => CryptoWeb.PBKDF2(password, salt, { iterations: 1000, keySize: 8 }),
                             () => Promise.resolve(CryptoJS.PBKDF2(password, salt, { iterations: 1000, keySize: 8 }))]);
      } else {
        targets.push([name, () => CryptoWeb[name](data), () => Promise.resolve(CryptoJS[cjName](data))]);
      }
    }
  }
  return targets;
}

(async () => {
  const targets = targetList();
  for (const [name, cwFn, cjFn] of targets) {
    for (let i = 0; i < 5; i++) {
      await cwFn();
      if (cjFn) await cjFn();
    }
    addBench(name, cwFn, cjFn);
  }

  suite.on('cycle', e => {
    const b = e.target;
    results.push({ name: b.name, hz: b.hz });
    console.log(String(b));
  })
  .on('complete', () => {
    fs.writeFileSync('bench-result.json', JSON.stringify({benchmarks:results}, null, 2));
    const tableLines = ['| API | CryptoWeb ops/s | CryptoJS ops/s | diff |',
                        '|-----|----------------|---------------|------|'];
    const cw = {}, cj = {};
    for (const r of results) {
      const [lib, name] = r.name.split(' ');
      if (lib === 'CryptoWeb') cw[name] = r.hz; else cj[name] = r.hz;
    }
    for (const api of Object.keys(cw)) {
      const cwHz = cw[api];
      const jsHz = cj[api];
      const cwCell = jsHz && cwHz > jsHz ? `**${cwHz.toFixed(2)}**` : (cwHz ? cwHz.toFixed(2) : '-');
      const jsCell = jsHz && jsHz > cwHz ? `**${jsHz.toFixed(2)}**` : (jsHz ? jsHz.toFixed(2) : '-');
      let diff = '-';
      if (cwHz && jsHz) {
        const ratio = cwHz > jsHz ? (cwHz/jsHz) : (jsHz/cwHz);
        diff = `${(ratio*100).toFixed(0)}%`;
      }
      tableLines.push(`| ${api} | ${cwCell} | ${jsCell} | ${diff} |`);
    }
    fs.writeFileSync('bench-table.md', tableLines.join('\n'));
  })
  .run({ async: true });
})();
