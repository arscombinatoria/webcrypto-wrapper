/* eslint-disable no-console */
const Benchmark = require('benchmark');
const CryptoWeb = require('../src');
const CryptoJS = require('crypto-js');
const fs = require('fs');

const suite = new Benchmark.Suite();
const plain = 'The quick brown fox jumps over the lazy dog';
const keyHex = '00112233445566778899aabbccddeeff';
const ivHex = '000102030405060708090a0b0c0d0e0f';

suite
  .add('CryptoWeb#SHA256', { defer: true, fn: d => CryptoWeb.SHA256(plain).then(() => d.resolve()) })
  .add('CryptoJS #SHA256', () => CryptoJS.SHA256(plain))
  .add('CryptoWeb#AES-encrypt', { defer: true,
    fn: d => CryptoWeb.AES.encrypt(plain, keyHex, { iv: ivHex }).then(() => d.resolve())
  })
  .add('CryptoJS #AES-encrypt', () =>
    CryptoJS.AES.encrypt(plain, CryptoJS.enc.Hex.parse(keyHex), { iv: CryptoJS.enc.Hex.parse(ivHex) })
  )
  .on('cycle', evt => console.log(String(evt.target)))
  .on('complete', function () {
    const rows = this.map(b => [b.name, b.hz.toFixed(0)]);
    const md = ['| test | ops/sec |', '| --- | ---: |',
      ...rows.map(([n, hz]) => `| ${n} | ${hz} |`)
    ].join('\n');
    fs.writeFileSync('bench-table.md', md);
    fs.writeFileSync('bench-result.json', JSON.stringify(this, null, 2));
  })
  .run({ async: true, minSamples: 20, maxTime: 0.5 });
