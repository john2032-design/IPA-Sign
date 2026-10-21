import crypto from 'node:crypto';

const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MIN_API_KEY_LENGTH = 32;
const MAX_API_KEY_LENGTH = 512;
const MAX_CLIENTS = 100;
const MAX_CLIENT_LIMIT = 100_000;
const MIN_WINDOW_MS = 60_000;
const MAX_WINDOW_MS = 24 * 60 * 60 * 1000;

function hashApiKey(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

function validatePositiveInteger(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

/**
 * Parse optional API_CLIENTS_JSON. The raw API key is immediately hashed; only its hash
 * and the client's quota remain in the returned map. An empty setting preserves legacy
 * public submission behavior.
 *
 * Expected format:
 * { "discord-production": { "key": "<32+ chars>", "limit": 120, "windowMs": 900000 } }
 */
export function loadApiClients(raw, {defaultLimit = 120, defaultWindowMs = 900_000} = {}) {
  validatePositiveInteger(defaultLimit, 'Default client limit', 1, MAX_CLIENT_LIMIT);
  validatePositiveInteger(defaultWindowMs, 'Default client windowMs', MIN_WINDOW_MS, MAX_WINDOW_MS);
  const input = String(raw ?? '').trim();
  if (!input) return new Map();

  let parsed;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new Error('API_CLIENTS_JSON must contain valid JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('API_CLIENTS_JSON must be a JSON object keyed by client ID.');
  }
  const entries = Object.entries(parsed);
  if (entries.length < 1 || entries.length > MAX_CLIENTS) {
    throw new Error(`API_CLIENTS_JSON must configure between 1 and ${MAX_CLIENTS} clients.`);
  }

  const clients = new Map();
  const seenKeyHashes = new Set();
  for (const [id, definition] of entries) {
    if (!CLIENT_ID_PATTERN.test(id)) throw new Error(`Invalid API client ID: ${id || '(empty)'}.`);
    if (!definition || typeof definition !== 'object' || Array.isArray(definition)) {
      throw new Error(`API client ${id} must be an object containing key and optional quota settings.`);
    }
    const key = typeof definition.key === 'string' ? definition.key : '';
    if (key.length < MIN_API_KEY_LENGTH || key.length > MAX_API_KEY_LENGTH) {
      throw new Error(`API client ${id} key must be between ${MIN_API_KEY_LENGTH} and ${MAX_API_KEY_LENGTH} characters.`);
    }
    const keyHash = hashApiKey(key);
    const keyHashHex = keyHash.toString('hex');
    if (seenKeyHashes.has(keyHashHex)) throw new Error(`Each API client must have a unique key (duplicate key configured for ${id}).`);
    seenKeyHashes.add(keyHashHex);

    const limit = definition.limit === undefined ? defaultLimit : definition.limit;
    const windowMs = definition.windowMs === undefined ? defaultWindowMs : definition.windowMs;
    validatePositiveInteger(limit, `API client ${id} limit`, 1, MAX_CLIENT_LIMIT);
    validatePositiveInteger(windowMs, `API client ${id} windowMs`, MIN_WINDOW_MS, MAX_WINDOW_MS);
    clients.set(id, {id, keyHash, limit, windowMs});
  }
  return clients;
}

/** Find a configured client using constant-time hash comparison; never log the supplied key. */
export function resolveApiClient(presentedKey, clients) {
  const key = typeof presentedKey === 'string' ? presentedKey : '';
  if (!key || key.length > MAX_API_KEY_LENGTH || !(clients instanceof Map) || clients.size === 0) return null;
  const suppliedHash = hashApiKey(key);
  let matched = null;
  for (const client of clients.values()) {
    if (crypto.timingSafeEqual(suppliedHash, client.keyHash)) matched = client;
  }
  return matched;
}

/** Consume one unit from this client's fixed-window quota. State is process-local. */
export function consumeApiClientQuota(client, windows, now = Date.now()) {
  if (!client || !(windows instanceof Map) || !Number.isFinite(now)) {
    throw new TypeError('A configured client, quota-window map, and finite timestamp are required.');
  }
  let bucket = windows.get(client.id);
  if (!bucket || now >= bucket.resetAt || now < bucket.startedAt) {
    bucket = {startedAt: now, resetAt: now + client.windowMs, count: 0};
    windows.set(client.id, bucket);
  }
  if (bucket.count >= client.limit) {
    return {
      allowed: false,
      limit: client.limit,
      remaining: 0,
      resetAt: bucket.resetAt,
      retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))
    };
  }
  bucket.count += 1;
  return {
    allowed: true,
    limit: client.limit,
    remaining: Math.max(0, client.limit - bucket.count),
    resetAt: bucket.resetAt,
    retryAfterSeconds: 0
  };
}
