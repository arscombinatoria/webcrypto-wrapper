const fs = require('fs');
const readme = fs.readFileSync('README.md','utf8');
const table  = fs.readFileSync('bench-table.md','utf8');
const updated = readme.replace(
  /<!-- BENCHMARK:START -->[^]*?<!-- BENCHMARK:END -->/,
  `<!-- BENCHMARK:START -->\n${table}\n<!-- BENCHMARK:END -->`
);
fs.writeFileSync('README.md', updated);
