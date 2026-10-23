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
assert(server.includes('getSignedUrl(getS3(), new GetObjectCommand'), 'large result downloads should continue to use direct presigned Tigris URLs');
assert(server.includes('DEFAULT_LOCAL_IPA_THRESHOLD_BYTES = 512 * 1024 * 1024'), 'the default local IPA tier must be 512 MiB');
assert(server.includes('keepUploadedIpaLocal = Boolean(!SHARED_QUEUE_ENABLED && !ipaUrl && ipaFile && ipaFile.size <= LOCAL_IPA_THRESHOLD_BYTES)'), 'small multipart IPA uploads must avoid Tigris only when local access is safe');
assert(server.includes('Downloaded IPA exceeds the ${formatBytesSafe(LOCAL_IPA_THRESHOLD_BYTES)} Render-local threshold. Staging source in Tigris'), 'large URL downloads must be staged in Tigris once actual size is known');
assert(server.includes('const keepSignedResultLocal = !SHARED_QUEUE_ENABLED && outputStat.size <= LOCAL_IPA_THRESHOLD_BYTES'), 'small signed results must use local storage only in the single-service mode');
assert(server.includes("app.get('/api/jobs/:id/download/:token'"), 'local signed results need a tokenized streamed download route');
assert(server.includes("app.get('/ota/:id/:token/signed.ipa'"), 'local signed results need an OTA IPA endpoint');
assert(server.includes('outputStat.size > MAX_IPA_BYTES'), 'signed output must respect the configured 4 GiB limit');
for (const [name, source] of [['render.yaml', render], ['README.md', readme], ['docs/SCALING.md', scaling], ['docs/index.html', html]]) {
  assert(source.includes('TIGRIS_UPLOAD_QUEUE_SIZE') && source.includes('TIGRIS_DOWNLOAD_CONCURRENCY'), `${name} must document Tigris tuning options`);
}
assert(render.includes('value: "16777216"'), 'Render blueprint should use 16 MiB multipart parts by default');
assert(render.includes('key: LOCAL_IPA_THRESHOLD_BYTES\n        value: "536870912"'), 'Render blueprint should default local IPA tier to 512 MiB');
for (const [name, source] of [['render.yaml', render], ['README.md', readme], ['docs/SCALING.md', scaling], ['docs/index.html', html]]) {
  assert(source.includes('LOCAL_IPA_THRESHOLD_BYTES'), `${name} must document the local/Tigris size tier`);
  assert(source.toLowerCase().includes('tmp') || source.includes('LOCAL_IPA_THRESHOLD_BYTES'), `${name} must document local storage behavior`);
}

console.log('Tigris/storage tier contract passed: bounded transfers, parallel range downloads, throughput logs, 512 MiB local tier, >512 MiB Tigris staging, and local/Tigris result delivery.');
