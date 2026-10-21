import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const docker = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
const yaml = fs.readFileSync(new URL('../render.yaml', import.meta.url), 'utf8');
const client = fs.readFileSync(new URL('../examples/discord-sign-api-client.js', import.meta.url), 'utf8');

assert(!source.includes("express.static(path.join(process.cwd(), 'public')"), 'API-only service must not serve frontend files');
assert(!source.includes("app.get('/api/owner/discord-api-docs'"), 'owner documentation UI/API should not ship in API-only mode');
assert(!source.includes("app.get('/api/config'"), 'browser config endpoint should not ship');
assert(!source.includes("app.post('/api/jobs', createLimiter"), 'browser multipart flow should not be exposed');
assert(!source.includes("app.get('/api/free-certificates/list/"), 'certificate browsing API should not ship');
assert(source.includes("app.get('/', (_req, res) => res.set('Cache-Control', 'no-store').json({"), 'root should return JSON API info, not HTML');
assert(source.includes("app.get(['/healthz', '/health']"), 'Render healthz readiness route must exist');
assert(yaml.includes('healthCheckPath: /healthz'), 'Render health check must target /healthz');
assert(source.includes("app.post(['/sign', '/api/v1/discord/sign']"), 'both /sign and Discord compatibility paths must exist');
assert(source.includes("app.get('/api/jobs/:id', pollLimiter"), 'bot must be able to poll signing status');
assert(source.includes("app.post('/api/jobs/:id/download-url'"), 'bot download URL endpoint missing');
assert(source.includes("app.post('/api/jobs/:id/ota-url'"), 'bot OTA URL endpoint missing');
assert(source.includes("app.get('/ota/:id/:token/manifest.plist'"), 'OTA manifest endpoint missing');
for (const field of ['certificate: MAX_SMALL_FILE_BYTES', 'profile: MAX_SMALL_FILE_BYTES', 'tweaks: 256 * 1024 * 1024']) {
  assert(source.includes(field), `bot file alias missing: ${field}`);
}
assert(source.includes("const p12File = file('p12') || file('certificate')"), 'certificate alias not mapped');
assert(source.includes("const profileFile = file('mobileprovision') || file('profile')"), 'profile alias not mapped');
assert(source.includes("file('deb') || legacyTweaks.find"), 'legacy tweaks .deb alias not mapped');
assert(source.includes("file('dylib') || legacyTweaks.find"), 'legacy tweaks .dylib alias not mapped');
assert(source.includes('body.appName || body.app_name || body.bundleName'), 'appName aliases missing');
assert(source.includes('body.bundleVersion || body.bundle_version || body.version'), 'version aliases missing');
assert(source.includes('const requestedSigner = clampText(body.signer, 32).toLowerCase()'), 'signer selection must be explicit');
assert(source.includes("requestedSigner !== 'zsign'"), 'unsupported signer should not silently fall back');
assert(source.includes('success: true, ok: true, jobId: manifest.id, job_id: manifest.id, jobToken: token'), 'submission response needs success, job ID, and token');
assert(source.includes('statusUrl, status_url: statusUrl, progressUrl: statusUrl, progress_url: statusUrl'), 'submission response needs bot polling URL aliases');
assert(source.includes('clientPollTokenHash'), 'legacy Discord bot shared-bearer polling compatibility missing');
assert(source.includes('response.result = await buildApiCompletionResult(manifest, req)'), 'completed job must include result object');
assert(source.includes('result.otaUrl = installUrl') && source.includes('result.downloadUrl = downloadUrl'), 'bot result needs OTA and download URL aliases');
assert(source.includes("success: false, ok: false, error: 'Too many signing requests"), 'rate-limit errors should be JSON');
assert(!docker.includes('COPY public ./public'), 'Docker image should not copy a website frontend');
assert(!yaml.includes('RECAPTCHA_SECRET_KEY'), 'API-only deployment should not require browser CAPTCHA');
assert(yaml.includes('API_SIGN_RATE_LIMIT'), 'API-only deployment should document/set a bot-friendly IP rate limit');
assert(client.includes('export async function submitAndPollXsign(input)'), 'Discord Node.js helper should expose submit + poll workflow');
assert(client.includes('Authorization: `Bearer ${initial.jobToken}`'), 'Discord helper must poll with the returned job-scoped token');
assert(client.includes("form.append('certificate'"), 'Discord helper must use the provided bot field aliases');
assert(client.includes("form.append('profile'"), 'Discord helper must send provisioning profile as a file');
assert(client.includes("form.append('ipaUrl', input.ipaUrl)"), 'Discord helper must support URL-only IPA source');

console.log('API-only routes, Discord.js upload aliases, polling, download/OTA results, and zsign contract checks passed.');
