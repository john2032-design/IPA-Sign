import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {Readable, Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';

const source = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const start = source.indexOf('async function downloadRemoteToFile(');
const end = source.indexOf("\napp.get(['/healthz', '/health']", start);
assert(start >= 0 && end > start, 'remote downloader function was not found');
const functionSource = source.slice(start, end);
const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'xsigner-remote-download-test-'));
const requestLog = [];
let fetchImpl;
const sandbox = {
  AbortSignal,
  Transform,
  Readable,
  URL,
  fs,
  fsp,
  path,
  pipeline,
  process: {env: {REMOTE_FETCH_TIMEOUT_MS: '60000', REMOTE_FETCH_USER_AGENT: 'test-xsigner-agent'}},
  validatePublicHttpsUrl: async value => value,
  formatBytesSafe: value => `${Number(value || 0)} bytes`,
  messageOf: error => error?.message || String(error),
  fetch: (...args) => fetchImpl(...args)
};
vm.createContext(sandbox);
vm.runInContext(`${functionSource}\nglobalThis.testDownloadRemoteToFile = downloadRemoteToFile;`, sandbox);
const download = sandbox.testDownloadRemoteToFile;

function responseFromBytes(status, buffer, headers = {}) {
  return new Response(new ReadableStream({
    start(controller) { controller.enqueue(buffer); controller.close(); }
  }), {status, headers});
}

try {
  const payload = Buffer.from('a streamed IPA payload for download verification');
  fetchImpl = async (url, options) => {
    requestLog.push({url, options});
    return responseFromBytes(200, payload, {'content-length': String(payload.length)});
  };
  const output = path.join(tempRoot, 'source.ipa');
  const progress = [];
  const received = await download('https://files.example.test/app.ipa', output, 1024 * 1024, (loaded, total) => progress.push([loaded, total]));
  assert.equal(received, payload.length);
  assert.deepEqual(await fsp.readFile(output), payload);
  assert.equal(progress.at(-1)[0], payload.length);
  assert.equal(progress.at(-1)[1], payload.length);
  assert.equal(requestLog[0].options.headers['user-agent'], 'test-xsigner-agent');
  assert.equal(requestLog[0].options.headers['accept-encoding'], 'identity');

  fetchImpl = async () => responseFromBytes(403, Buffer.from('forbidden'));
  await assert.rejects(
    () => download('https://blocked.example.test/app.ipa', path.join(tempRoot, 'forbidden.ipa'), 1024),
    /blocked\.example\.test refused the download \(HTTP 403\).*source-host access restriction/i
  );

  fetchImpl = async () => responseFromBytes(200, Buffer.from('too large'), {'content-length': '9'});
  await assert.rejects(
    () => download('https://files.example.test/big.ipa', path.join(tempRoot, 'oversized.ipa'), 4),
    /exceeding the configured 4 bytes IPA limit/i
  );

  console.log('Remote-download tests passed: streaming file write, configurable headers, source-host 403 diagnostic, and size-limit rejection.');
} finally {
  await fsp.rm(tempRoot, {recursive: true, force: true});
}
