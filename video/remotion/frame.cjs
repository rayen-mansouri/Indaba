const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const root = path.resolve(__dirname, '..');
const clip = process.argv[2];
const seconds = Number(process.argv[3]);
if (!clip || !Number.isFinite(seconds) || seconds < 0) {
  console.error('Usage: npm run frame -- <clip-name> <seconds>');
  process.exit(1);
}
const ffmpeg = process.env.FFMPEG || 'ffmpeg';
const input = path.resolve(root, clip);
const output = path.resolve(root, 'qa', `${path.basename(clip, path.extname(clip))}-${seconds}s.png`);
fs.mkdirSync(path.dirname(output), { recursive: true });
const result = spawnSync(ffmpeg, ['-y', '-ss', String(seconds), '-i', input, '-frames:v', '1', output], { stdio: 'inherit' });
if (result.status !== 0) process.exit(result.status || 1);
console.log(output);
