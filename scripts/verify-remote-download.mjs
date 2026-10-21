import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {EventEmitter} from 'node:events';
import {Readable, Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import net from 'node:net';

const source = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const networkStart = source.indexOf('function ipv6Words(');
const downloaderStart = source.indexOf('async function downloadRemoteToFile(');
const downloaderEnd = source.indexOf("app.get(['/healthz', '/health']", downloaderStart);
assert(networkStart >= 0 && downloaderStart > networkStart && downloaderEnd > downloaderStart, 'URL security/downloader functions were not found');
const networkBlock = source.slice(networkStart, source.indexOf('\nfunction remoteFilename(', networkStart));
const downloaderBlock = source.slice(downloaderStart, downloaderEnd);
const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'xsigner-remote-download-test-'));
const requestLog = [];
let responsePlans = [];
const dns = {
  async lookup(hostname, options) {
    const host = String(hostname).toLowerCase();
    const map = {
      'private.example.test': [{address: '10.1.2.3', family: 4}],
      'linklocal.example.test': [{address: '169.254.169.254', family: 4}],
      'v6private.example.test': [{address: 'fd00::1234', family: 6}],
      'v6linklocal.example.test': [{address: 'fe80::1', family: 6}],
      'v6documentation.example.test': [{address: '2001:db8::1', family: 6}],
      'mapped-v4.example.test': [{address: '::ffff:127.0.0.1', family: 6}]
    };
    const result = map[host] || [{address: '93.184.216.34', family: 4}, {address: '2606:2800:220:1:248:1893:25c8:1946', family: 6}];
    if (options?.all) return result;
    return result[0];
  }
};
const https = {
  request(url, options, callback) {
    const parsed = new URL(url);
    const req = new EventEmitter();
    let destroyed = false;
    req.end = () => {
      options.lookup(parsed.hostname, {all: true}, (error, addresses) => {
        if (destroyed) return;
        if (error) return req.emit('error', error);
        requestLog.push({url: parsed.toString(), options, pinnedAddresses: addresses});
        const plan = responsePlans.shift() || {status: 200, payload: Buffer.from('default payload')};
        const response = Readable.from(plan.payload ? [plan.payload] : []);
        response.statusCode = plan.status;
        response.headers = Object.fromEntries(Object.entries(plan.headers || {}).map(([key, value]) => [key.toLowerCase(), value]));
        callback(response);
      });
    };
    req.destroy = error => { destroyed = true; if (error) req.emit('error', error); };
    return req;
  }
};
const sandbox = {
  AbortSignal, Transform, Readable, URL, fs, fsp, path, pipeline, net, dns, https,
  process: {env: {REMOTE_FETCH_TIMEOUT_MS: '60000', REMOTE_FETCH_USER_AGENT: 'test-xsigner-agent'}},
  formatBytesSafe: value => `${Number(value || 0)} bytes`,
  messageOf: error => error?.message || String(error)
};
vm.createContext(sandbox);
vm.runInContext(`${networkBlock}\n${downloaderBlock}\nglobalThis.urlTests = {isPrivateAddress, resolvePublicHttpsUrl, validatePublicHttpsUrl, downloadRemoteToFile};`, sandbox);
const {isPrivateAddress, resolvePublicHttpsUrl, downloadRemoteToFile} = sandbox.urlTests;

try {
  assert.equal(isPrivateAddress('127.0.0.1'), true);
  assert.equal(isPrivateAddress('10.0.0.5'), true);
  assert.equal(isPrivateAddress('100.64.0.1'), true);
  assert.equal(isPrivateAddress('169.254.169.254'), true);
  assert.equal(isPrivateAddress('192.0.2.1'), true);
  assert.equal(isPrivateAddress('198.51.100.2'), true);
  assert.equal(isPrivateAddress('203.0.113.9'), true);
  assert.equal(isPrivateAddress('::1'), true);
  assert.equal(isPrivateAddress('fd00::1'), true);
  assert.equal(isPrivateAddress('fe80::1'), true);
  assert.equal(isPrivateAddress('2001:db8::1'), true);
  assert.equal(isPrivateAddress('2606:2800:220:1:248:1893:25c8:1946'), false);
  await assert.rejects(() => resolvePublicHttpsUrl('https://private.example.test/app.ipa'), /globally routable public IP/);
  await assert.rejects(() => resolvePublicHttpsUrl('https://linklocal.example.test/app.ipa'), /globally routable public IP/);
  await assert.rejects(() => resolvePublicHttpsUrl('https://v6private.example.test/app.ipa'), /globally routable public IP/);
  await assert.rejects(() => resolvePublicHttpsUrl('https://v6linklocal.example.test/app.ipa'), /globally routable public IP/);
  await assert.rejects(() => resolvePublicHttpsUrl('https://v6documentation.example.test/app.ipa'), /globally routable public IP/);
  await assert.rejects(() => resolvePublicHttpsUrl('https://mapped-v4.example.test/app.ipa'), /globally routable public IP/);
  await assert.rejects(() => resolvePublicHttpsUrl('http://files.example.test/app.ipa'), /public HTTPS URL/);

  const payload = Buffer.from('a streamed IPA payload for download verification');
  responsePlans = [{status: 200, payload, headers: {'content-length': String(payload.length)}}];
  requestLog.length = 0;
  const output = path.join(tempRoot, 'source.ipa');
  const progress = [];
  const received = await downloadRemoteToFile('https://files.example.test/app.ipa', output, 1024 * 1024, (loaded, total) => progress.push([loaded, total]));
  assert.equal(received, payload.length);
  assert.deepEqual(await fsp.readFile(output), payload);
  assert.equal(progress.at(-1)[0], payload.length);
  assert.equal(progress.at(-1)[1], payload.length);
  assert.equal(requestLog[0].options.headers['user-agent'], 'test-xsigner-agent');
  assert.equal(requestLog[0].options.headers['accept-encoding'], 'identity');
  assert.equal(requestLog[0].pinnedAddresses[0].address, '93.184.216.34', 'the network request must use the previously validated DNS answer');
  assert.equal(requestLog[0].options.servername, 'files.example.test', 'TLS must still verify against the hostname after DNS pinning');

  responsePlans = [{status: 302, payload: Buffer.alloc(0), headers: {location: 'https://redirect.example.test/new.ipa'}}, {status: 200, payload, headers: {'content-length': String(payload.length)}}];
  requestLog.length = 0;
  const redirectOutput = path.join(tempRoot, 'redirect.ipa');
  await downloadRemoteToFile('https://files.example.test/redirect.ipa', redirectOutput, 1024 * 1024);
  assert.equal(requestLog.length, 2, 'a safe redirect should be followed');
  assert.equal(requestLog[1].url, 'https://redirect.example.test/new.ipa');
  assert.equal(requestLog[1].pinnedAddresses[0].address, '93.184.216.34', 'redirect destinations must be resolved and pinned independently');

  responsePlans = [{status: 403, payload: Buffer.from('forbidden')}];
  await assert.rejects(
    () => downloadRemoteToFile('https://blocked.example.test/app.ipa', path.join(tempRoot, 'forbidden.ipa'), 1024),
    /blocked\.example\.test refused the download \(HTTP 403\).*source-host access restriction/i
  );

  responsePlans = [{status: 200, payload: Buffer.from('too large'), headers: {'content-length': '9'}}];
  await assert.rejects(
    () => downloadRemoteToFile('https://files.example.test/big.ipa', path.join(tempRoot, 'oversized.ipa'), 4),
    /exceeding the configured 4 bytes IPA limit/i
  );

  console.log('Remote-download tests passed: stream writing, DNS pinning, public-only IPv4/IPv6 filtering, safe redirects, host 403 diagnostics, and size limit enforcement.');
} finally {
  await fsp.rm(tempRoot, {recursive: true, force: true});
}
