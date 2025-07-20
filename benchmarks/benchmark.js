const CryptoWeb = require('../src');
const CryptoJS = require('crypto-js');
const { performance } = require('node:perf_hooks');
const { webcrypto } = require('node:crypto');

global.crypto = webcrypto;

async function measure(fn, iterations = 10) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const end = performance.now();
  return (end - start) / iterations;
}

async function runBench(name, webFn, jsFn, iterations = 10) {
  const web = await measure(webFn, iterations);
  const js = await measure(jsFn, iterations);
  const ratio = js / web;
  console.log(`${name}: CryptoWeb ${web.toFixed(2)}ms/op, crypto-js ${js.toFixed(2)}ms/op (${ratio.toFixed(1)}x)`);
  return { name, web, js, ratio };
}

(async () => {
  const data = 'x'.repeat(1024 * 1024); // 1MiB string
  const key = '00112233445566778899aabbccddeeff';
  const results = [];
  results.push(await runBench('AES.encrypt', () => CryptoWeb.AES.encrypt(data, key), () => CryptoJS.AES.encrypt(data, key)));
  results.push(await runBench('SHA256', () => CryptoWeb.SHA256(data), () => Promise.resolve(CryptoJS.SHA256(data))));

  console.log('\nSummary (ms per operation):');
  for (const r of results) {
    console.log(`${r.name}: CryptoWeb ${r.web.toFixed(2)}, crypto-js ${r.js.toFixed(2)}, ${r.ratio.toFixed(1)}x`);
  }
})();
