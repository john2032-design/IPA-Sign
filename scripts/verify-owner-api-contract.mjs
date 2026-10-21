import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const ownerStart = source.indexOf('function normalizeIp(value)');
const ownerEnd = source.indexOf('function storageConfigured()', ownerStart);
assert(ownerStart >= 0 && ownerEnd > ownerStart, 'owner-IP helper block was not found');
const ownerCode = source.slice(ownerStart, ownerEnd);
const sandbox = {
  net,
  process: {env: {NODE_ENV: 'production', OWNER_IP: '168.91.23.165'}},
};
vm.createContext(sandbox);
vm.runInContext(`${ownerCode}\nglobalThis.ownerIpTest = {normalizeIp, normalizedClientIp, ownerIpDetectionSource, isOwnerRequest};`, sandbox);
const owner = sandbox.ownerIpTest;

assert.equal(owner.normalizeIp('168.91.23.165'), '168.91.23.165');
assert.equal(owner.normalizeIp('::ffff:168.91.23.165'), '168.91.23.165');
assert.equal(owner.isOwnerRequest({headers: {'cf-connecting-ip': '168.91.23.165'}}), true,
  'the configured owner IPv4 should be recognized from Cloudflare client-IP header');
assert.equal(owner.isOwnerRequest({headers: {'cf-connecting-ip': '::ffff:168.91.23.165'}}), true,
  'IPv4-mapped IPv6 should normalize to the configured owner IPv4');
assert.equal(owner.isOwnerRequest({headers: {'cf-connecting-ip': '203.0.113.9'}}), false,
  'non-owner IP must not see owner API documentation');
assert.equal(owner.isOwnerRequest({headers: {'x-forwarded-for': '168.91.23.165'}, socket: {remoteAddress: '10.0.0.4'}}), false,
  'untrusted X-Forwarded-For must not bypass the owner-IP check');
assert.equal(owner.ownerIpDetectionSource({headers: {'cf-connecting-ip': '168.91.23.165'}}), 'cf-connecting-ip');
assert.equal(owner.normalizedClientIp({headers: {}, socket: {remoteAddress: '10.0.0.4'}}), '',
  'production must fail closed when the trusted Cloudflare header is missing');

// Contract assertions for the Discord bot's form-data field aliases and polling response.
for (const field of ['certificate: MAX_SMALL_FILE_BYTES', 'profile: MAX_SMALL_FILE_BYTES', 'tweaks: 256 * 1024 * 1024']) {
  assert(source.includes(field), `missing upload compatibility limit: ${field}`);
}
assert(source.includes("app.post(['/sign', '/api/v1/discord/sign']"), 'public /sign and bot alias route missing');
assert(source.includes('success: true, ok: true, jobId: manifest.id'), 'submission response must include success=true');
assert(source.includes('statusUrl, status_url: statusUrl, progressUrl: statusUrl, progress_url: statusUrl'), 'submission response polling URL aliases missing');
assert(source.includes('clientPollTokenHash'), 'job-scoped compatibility bearer hash missing');
assert(source.includes('response.result = await buildApiCompletionResult(manifest, req)'), 'completed jobs must return a result payload');
assert(source.includes('result.otaUrl = installUrl') && source.includes('result.downloadUrl = downloadUrl'), 'result payload must include OTA and download links');

console.log('Owner-IP and Discord /sign API contract checks passed.');
