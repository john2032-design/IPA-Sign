import assert from 'node:assert/strict';
import fs from 'node:fs';
import {loadApiClients, resolveApiClient, consumeApiClientQuota} from '../lib/api-client-auth.js';
import {removeSecretValue, safeTerminalLine} from '../lib/log-sanitizer.js';

const server = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const docs = fs.readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');
const openapi = JSON.parse(fs.readFileSync(new URL('../docs/openapi.json', import.meta.url), 'utf8'));
const yaml = fs.readFileSync(new URL('../render.yaml', import.meta.url), 'utf8');

// Status sanitization regression: normal status text never receives a password argument.
assert(!server.includes('[REDACTED]'), 'server code must not insert a [REDACTED] placeholder');
assert(server.includes("import {removeSecretValue, safeTerminalLine} from './lib/log-sanitizer.js';"), 'server must use the dedicated log sanitizer');
assert(server.includes('const clean = safeTerminalLine(message);'), 'app-generated status text must be scrubbed without a P12 password');
assert(server.includes('const scrub = text => removeSecretValue(text, passwordForRedaction);'), 'raw zsign output must still remove secrets');
assert(server.includes('throw new Error(removeSecretValue(detail, password));'), 'zsign error detail must be scrubbed without a placeholder');
assert(!/appendJobLog\([^\n]*,\s*password\);/.test(server), 'status logger calls must not pass a P12 password');
assert.equal(removeSecretValue('Progress: 42%', '2'), 'Progress: 42%', 'short secret must not alter embedded progress digits');
assert.equal(safeTerminalLine('>>> Progress: 2 / 2', '2'), '>>> Progress: 2 / 2', 'short secret must not destroy zsign operation counters');
assert.equal(safeTerminalLine('password=2 is invalid', '2'), 'password= is invalid', 'short secret in an explicit password assignment must be removed');
assert.equal(safeTerminalLine('Authentication failed: password=VeryStrong#Key42', 'VeryStrong#Key42'), 'Authentication failed: password=', 'long secrets must be removed without a placeholder');
assert.equal(safeTerminalLine('Archiving signed IPA 2/2\u001b[0m', '2'), 'Archiving signed IPA 2/2', 'ANSI cleanup must not mangle progress text');

// Optional auth: no JSON config preserves the current no-key contract.
assert.equal(loadApiClients('').size, 0, 'unset API_CLIENTS_JSON must keep auth disabled');
const productionKey = 'Pp4!xsigner-production-key-that-is-long-enough-123';
const stagingKey = 'Ss9!xsigner-staging-key-is-also-at-least-32-characters';
const clients = loadApiClients(JSON.stringify({
  'discord-production': {key: productionKey, limit: 2, windowMs: 60_000},
  'discord-staging': {key: stagingKey}
}), {defaultLimit: 120, defaultWindowMs: 900_000});
assert.equal(resolveApiClient(productionKey, clients).id, 'discord-production');
assert.equal(resolveApiClient('incorrect-key', clients), null);
assert.equal(clients.get('discord-production').keyHash.includes(productionKey), false, 'raw API key must not be stored in the client configuration');
assert.equal(clients.get('discord-staging').limit, 120, 'default per-client quota should be applied');
assert.equal(clients.get('discord-staging').windowMs, 900_000, 'default window should be applied');

const windows = new Map();
const client = clients.get('discord-production');
assert.equal(consumeApiClientQuota(client, windows, 1_000_000).remaining, 1);
assert.equal(consumeApiClientQuota(client, windows, 1_000_001).remaining, 0);
const rejected = consumeApiClientQuota(client, windows, 1_000_002);
assert.equal(rejected.allowed, false);
assert.equal(rejected.retryAfterSeconds, 60);
assert.equal(consumeApiClientQuota(client, windows, 1_060_000).allowed, true, 'quota must reset at the window boundary');
assert.throws(() => loadApiClients('{bad json'), /valid JSON/);
assert.throws(() => loadApiClients(JSON.stringify({'short': {key: 'short'}})), /between 32 and 512 characters/);
assert.throws(() => loadApiClients(JSON.stringify({'duplicate1': {key: productionKey}, 'duplicate2': {key: productionKey}})), /unique key/);
assert.throws(() => loadApiClients(JSON.stringify({'bad-limit': {key: productionKey, limit: 0}})), /limit must be an integer/);

// Route middleware order: authenticate/quota before multipart parsing; legacy requests skip it when config is unset.
assert(server.includes('if (API_CLIENTS.size === 0) return next();'), 'API key checks must be opt-in');
assert(server.includes("req.get('x-api-key') || ''"), 'submission must read X-API-Key');
assert(server.includes("code: 'API_KEY_REQUIRED'"), 'missing/invalid API keys must get an explicit 401 code');
assert(server.includes("code: 'API_CLIENT_RATE_LIMITED'"), 'per-client quota overflow must have a stable error code');
assert(server.includes('skip: req => Boolean(req.apiClient)'), 'authenticated clients should use client quota instead of anonymous IP quota');
assert(server.includes('skip: req => !req.apiClient'), 'authenticated traffic should also have a separate IP safety ceiling');
assert(server.includes("app.post(['/sign', '/api/v1/discord/sign'], authenticateApiClientAndApplyQuota, publicSignLimiter, authenticatedSignIpLimiter, handleApiSignUpload"), 'auth and quotas must run before receiving/parsing multipart uploads');
assert(yaml.includes('key: API_CLIENT_DEFAULT_LIMIT') && yaml.includes('key: API_CLIENT_DEFAULT_WINDOW_MS') && yaml.includes('key: API_SIGN_AUTHENTICATED_IP_LIMIT'), 'Render default quotas must be documented in the Blueprint');
assert(readme.includes('API_CLIENTS_JSON') && readme.includes('X-API-Key'), 'README must explain optional API-key mode');
assert(docs.includes('id="client-auth"') && docs.includes('X-API-Key'), 'documentation must describe optional API-key authentication');
assert(openapi.components.securitySchemes.apiKeyAuth.name === 'X-API-Key', 'OpenAPI must declare X-API-Key');
assert(openapi.paths['/sign'].post.responses['401'], 'OpenAPI must document authentication errors');
assert(openapi.paths['/sign'].post.responses['429'], 'OpenAPI must document client quota errors');
assert(openapi.paths['/sign'].post.security.some(item => item.apiKeyAuth), 'OpenAPI should include conditional API-key auth');
const discordClient = fs.readFileSync(new URL('../examples/discord-sign-api-client.js', import.meta.url), 'utf8');
assert(discordClient.includes("input.apiKey ? {'X-API-Key': String(input.apiKey)} : {}"), 'Discord helper should send API key only when provided');

console.log('Security regression checks passed: status text, short-password handling, optional per-client API keys, quotas, and documentation.');
