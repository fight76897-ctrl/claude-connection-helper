const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const output = process.argv[2] ? path.resolve(process.argv[2]) : path.join(root, 'dist/ClaudeConnectionHelper-win32-x64');
fs.mkdirSync(path.join(output, 'docs'), { recursive: true });
for (const [source, destination] of [
  ['README.md', '使用说明.md'],
  ['docs/validation.md', 'docs/validation.md'],
  ['scripts/restore-network.cmd', 'restore-network.cmd'],
  ['scripts/restore-network.ps1', 'restore-network.ps1'],
]) fs.copyFileSync(path.join(root, source), path.join(output, destination));
console.log('Included usage instructions and standalone network recovery.');
