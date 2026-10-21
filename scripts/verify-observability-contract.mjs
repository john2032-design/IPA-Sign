import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');
const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const spec = JSON.parse(fs.readFileSync(new URL('../docs/openapi.json', import.meta.url), 'utf8'));

assert(source.includes("res.setHeader('X-Request-ID', req.requestId)"), 'all requests must receive a server-controlled request ID');
assert(source.includes("requestId: req.requestId"), 'JSON error responses must include requestId');
assert(source.includes('code: typeof body.code === \'string\' && body.code ? body.code : defaultCode'), 'JSON errors must include stable machine-readable codes');
assert(source.includes("app.get('/healthz/dependencies', async"), 'cached dependency diagnostics route is missing');
assert(source.includes("app.get('/api/ops/metrics', requireOwnerDocs, async"), 'owner-only operations metrics route is missing');
assert(source.includes("signingQueue.getJobCounts('waiting', 'active', 'delayed', 'completed', 'failed', 'waiting-children', 'prioritized')"), 'shared queue depth must be observable');
assert(source.includes('await fsp.statfs(ROOT)'), 'operational metrics must report scratch disk availability without applying a limit');
assert(source.includes("event: 'signing_job_started'") && source.includes("event: 'signing_job_completed'") && source.includes("event: 'signing_job_failed'"), 'structured job timing/failure events are required');
assert(source.includes("event: 'signing_submission_failed'"), 'submission/upload failure telemetry is required');
assert(source.includes('new HeadBucketCommand({Bucket: BUCKET})'), 'dependency diagnostics must check actual bucket reachability');
assert(source.includes("execFileAsync(SIGNER, ['-v']"), 'dependency diagnostics must execute the signer with a timeout');
assert(source.includes('apiDiagnosticCacheMs'), 'expensive dependency checks must be cached');
assert(source.includes('const SIGNED_IPA_RETENTION_MINUTES = Number.isFinite(SIGNED_IPA_RETENTION_CONFIG) ? Math.min(60, Math.max(1, SIGNED_IPA_RETENTION_CONFIG)) : 10'), 'result retention must be configurable and bounded to 1–60 minutes');
assert(source.includes('resultExpiresAt: new Date(') && source.includes('resultExpiresAtMs:'), 'job results must expose the exact retention deadline');
assert(source.includes('expiresAtMs'), 'download and OTA URL responses must include expiration timestamps');
assert(html.includes('/healthz/dependencies'), 'API docs must describe deeper health diagnostics');
assert(html.includes('X-Request-ID') && html.includes('requestId'), 'API docs must explain request correlation IDs');
assert(html.includes('resultExpiresAt') && html.includes('1–60'), 'API docs must explain configurable expiry');
assert(spec.paths['/healthz/dependencies'], 'OpenAPI must describe dependency diagnostics');
assert(spec.components.schemas.Error.properties.requestId, 'OpenAPI errors must describe requestId');
assert(spec.components.headers.RequestIdHeader, 'OpenAPI must define X-Request-ID as a response header');
for (const [path, item] of Object.entries(spec.paths)) for (const [method, operation] of Object.entries(item)) if (operation.responses) for (const [status, response] of Object.entries(operation.responses)) assert(response.headers?.['X-Request-ID'], `OpenAPI ${method.toUpperCase()} ${path} response ${status} must document X-Request-ID`);
assert(readme.includes('Error responses and request tracing') && readme.includes('horizontal scaling'), 'README must describe stable error shape and scale-out mode');

console.log('Observability and retention checks passed: request IDs, standard error codes, dependency diagnostics and bounded result expiry.');
