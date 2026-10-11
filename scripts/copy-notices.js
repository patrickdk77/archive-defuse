// Copies the license and notice of the code taken from lzma1 next to its build in dist/lzma1, so they ship with it.
const fs = require('node:fs');
const path = require('node:path');
const from = path.join(__dirname, '..', 'src', 'lzma1');
const to = path.join(__dirname, '..', 'dist', 'lzma1');
for (const name of ['LICENSE', 'NOTICE']) fs.copyFileSync(path.join(from, name), path.join(to, name));
console.log('dist/lzma1: LICENSE and NOTICE');
