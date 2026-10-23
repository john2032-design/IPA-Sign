import assert from 'node:assert/strict';
import fs from 'node:fs';

const server = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const render = fs.readFileSync(new URL('../render.yaml', import.meta.url), 'utf8');
const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const scaling = fs.readFileSync(new URL('../docs/SCALING.md', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');

assert(server.includes('Number(process.env.PART_SIZE_BYTES ?? DEFAULT_TIGRIS_PART_SIZE_BYTES)'), 'multipart part size must be configurable');
assert(server.includes('queueSize: TIGRIS_UPLOAD_QUEUE_SIZE, partSize: PART_SIZE'), 'Tigris multipart upload concurrency must be configurable');
assert(server.includes('Promise.allSettled(batch.map(async ([source, kind])'), 'input object uploads should run in bounded concurrent batches');
assert(server.includes('Promise.allSettled(batch.map(async ([kind, upload])'), 'input downloads should run in bounded concurrent batches');
assert(server.includes('Range: `bytes=${start}-${end}`'), 'large Tigris object downloads should use ranged GET requests');
assert(server.includes('response.$metadata?.httpStatusCode !== 206'), 'ranged downloads must validate partial-content responses');
assert(server.includes('bytesReceived !== expectedRangeBytes'), 'each ranged download must verify its received byte count');
assert(server.includes('Tigris input upload completed: ${kind}') && server.includes('Tigris input download completed: ${kind}'), 'transfer logs should include timing and throughput');
assert(server.includes('getSignedUrl(getS3(), new GetObjectCommand'), 'result downloads should continue to use direct presigned Tigris URLs');
for (const [name, source] of [['render.yaml', render], ['README.md', readme], ['docs/SCALING.md', scaling], ['docs/index.html', html]]) {
  assert(source.includes('TIGRIS_UPLOAD_QUEUE_SIZE') && source.includes('TIGRIS_DOWNLOAD_CONCURRENCY'), `${name} must document Tigris tuning options`);
}
assert(render.includes('value: "16777216"'), 'Render blueprint should use 16 MiB multipart parts by default');

console.log('Tigris performance contract passed: bounded multipart/object concurrency, parallel range downloads, throughput logging, and direct presigned result URLs.');
