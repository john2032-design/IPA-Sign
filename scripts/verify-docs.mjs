import assert from 'node:assert/strict';
import fs from 'node:fs';

const server = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');
const openapi = JSON.parse(fs.readFileSync(new URL('../docs/openapi.json', import.meta.url), 'utf8'));
const docker = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
const render = fs.readFileSync(new URL('../render.yaml', import.meta.url), 'utf8');

assert(server.includes("app.get(['/doc', '/doc/'], requireOwnerDocs"), 'owner-only /doc route must be registered');
assert(server.includes("app.get('/doc/openapi.json', requireOwnerDocs"), 'machine-readable OpenAPI route must also be owner-only');
assert(server.includes("process.env.OWNER_IP || process.env.XSIGNER_OWNER_IP || '168.91.23.165'"), 'owner IP must use OWNER_IP and the expected fallback');
assert(server.includes("req.headers?.['cf-connecting-ip']"), 'owner check must use the trusted edge IP header on Render');
assert(server.includes("app.post(['/sign', '/api/v1/discord/sign']"), 'public /sign routes missing');
assert(server.includes("app.get('/api/jobs/:id', pollLimiter"), 'job polling endpoint missing');
assert(server.includes("app.post('/api/jobs/:id/download-url'"), 'download endpoint missing');
assert(server.includes("app.post('/api/jobs/:id/ota-url'"), 'OTA endpoint missing');
assert(server.includes("app.get('/ota/:id/:token/manifest.plist'"), 'OTA manifest endpoint missing');
assert(server.includes("status: ready ? 'ok' : 'degraded'"), 'Discord health endpoint must not claim ok when dependencies are missing');
assert(docker.includes('COPY docs ./docs'), 'Docker image must contain static documentation');
assert(/key: OWNER_IP\s+value: 168\.91\.23\.165/.test(render), 'Render Blueprint must declare the configured owner IP');
for (const section of ['id="quick-start"','id="fields"','id="lifecycle"','id="endpoints"','id="success"','id="errors"','id="discord"','id="storage"']) {
  assert(html.includes(section), `Documentation is missing section ${section}`);
}
for (const field of ['ipaUrl','mobileprovision','certificate','profile','bundleId','bundleVersion','injectExtensions','tweaks','downloadUrl','otaUrl','429','503','403']) {
  assert(html.includes(field), `Documentation is missing field/topic ${field}`);
}
for (const route of ['/sign','/api/v1/discord/sign','/api/jobs/{jobId}','/api/jobs/{jobId}/download-url','/api/jobs/{jobId}/ota-url','/ota/{jobId}/{token}/manifest.plist','/health','/api/v1/discord/health']) {
  assert(openapi.paths[route], `OpenAPI document is missing ${route}`);
}
assert(openapi.info.version && openapi.openapi === '3.1.0', 'OpenAPI metadata is invalid');
console.log('Owner-only /doc page, OpenAPI routes, fields, response/error docs, and Docker packaging checks passed.');

assert(server.includes("app.get('/api/ops/metrics', requireOwnerDocs, async"), 'owner-only operational metrics endpoint missing');
assert(html.includes('/api/ops/metrics'), 'API docs must document owner-only operational metrics');
assert(openapi.paths['/api/ops/metrics']?.get, 'OpenAPI must document operational metrics');
