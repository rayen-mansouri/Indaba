const fs = require('node:fs');
const path = require('node:path');

const file = path.resolve(__dirname, '..', 'effects.json');
const data = JSON.parse(fs.readFileSync(file, 'utf8'));
if (data.fps !== 30 || data.width !== 1920 || data.height !== 1080 || !Number.isFinite(data.duration) || !Array.isArray(data.clips) || data.clips.length === 0) {
  throw new Error('effects.json must define 1920x1080/30fps and at least one clip');
}
if (!Array.isArray(data.segments) || data.segments.length === 0) throw new Error('effects.json must define badge segments');
let cursor = 0;
for (const [index, segment] of data.segments.entries()) {
  if (segment.start !== cursor || segment.end <= segment.start || !['LIVE', 'REPLAY', 'MOCK'].includes(segment.label)) {
    throw new Error(`segments must be sorted, contiguous, and valid at index ${index}`);
  }
  cursor = segment.end;
}
if (cursor !== data.duration) throw new Error(`segments end at ${cursor}, expected ${data.duration}`);
const allowed = new Set(['zoom', 'highlight', 'callout', 'caption', 'titleCard']);
for (const [clipIndex, clip] of data.clips.entries()) {
  if (!clip.file || !['LIVE', 'REPLAY', 'MOCK'].includes(clip.label) || !Array.isArray(clip.effects)) throw new Error(`invalid clip ${clipIndex}`);
  for (const [effectIndex, effect] of clip.effects.entries()) {
    if (!allowed.has(effect.type)) throw new Error(`unsupported effect ${effect.type} at ${clipIndex}/${effectIndex}`);
    if (effect.type !== 'titleCard' && !(effect.t1 > effect.t0)) throw new Error(`invalid time range at ${clipIndex}/${effectIndex}`);
  }
}
console.log(`PASS: ${data.clips.length} clip(s), ${data.clips.reduce((n, c) => n + c.effects.length, 0)} effect(s)`);
