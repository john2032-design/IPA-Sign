import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import dns from 'node:dns/promises';
import net from 'node:net';
import https from 'node:https';
import {spawn, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import multer from 'multer';
import {pipeline} from 'node:stream/promises';
import {Transform, Readable} from 'node:stream';
import {
  S3Client, AbortMultipartUploadCommand,
  PutObjectCommand, GetObjectCommand,
  DeleteObjectCommand, ListObjectsV2Command, HeadBucketCommand
} from '@aws-sdk/client-s3';
import {getSignedUrl} from '@aws-sdk/s3-request-presigner';
import {Upload} from '@aws-sdk/lib-storage';
import {Queue, Worker} from 'bullmq';
import IORedis from 'ioredis';
import {loadApiClients, resolveApiClient, consumeApiClientQuota} from './lib/api-client-auth.js';
import {removeSecretValue, safeTerminalLine} from './lib/log-sanitizer.js';

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 10000);
const ROOT = process.env.DATA_DIR || '/tmp/xsigner-data';
const WORK_ROOT = path.join(ROOT, 'work');
const MANIFEST_ROOT = path.join(ROOT, 'manifests');
const SIGNER = process.env.ZSIGN_BIN || '/usr/local/bin/zsign';
const BUCKET = process.env.S3_BUCKET || process.env.TIGRIS_BUCKET || '';
const REGION = process.env.AWS_REGION || 'auto';
const ENDPOINT = process.env.AWS_ENDPOINT_URL_S3 || process.env.AWS_ENDPOINT_URL || 'https://t3.storage.dev';
const MAX_IPA_BYTES = Number(process.env.MAX_IPA_BYTES || 4294967296);
const MAX_SMALL_FILE_BYTES = 16 * 1024 * 1024;
const PART_SIZE = Number(process.env.PART_SIZE_BYTES || 64 * 1024 * 1024);
const JOB_TTL_MS = Number(process.env.JOB_TTL_HOURS || 24) * 60 * 60 * 1000;
const UPLOAD_TTL_MS = Number(process.env.UPLOAD_TTL_HOURS || 6) * 60 * 60 * 1000;
const STALE_JOB_MS = Number(process.env.STALE_JOB_MINUTES || 45) * 60 * 1000;
const SIGNED_IPA_RETENTION_CONFIG = Number(process.env.SIGNED_IPA_TTL_MINUTES);
const SIGNED_IPA_RETENTION_MINUTES = Number.isFinite(SIGNED_IPA_RETENTION_CONFIG) ? Math.min(60, Math.max(1, SIGNED_IPA_RETENTION_CONFIG)) : 10;
const SIGNED_IPA_RETENTION_MS = Math.max(60_000, SIGNED_IPA_RETENTION_MINUTES * 60 * 1000);
const SIGNED_IPA_CLEANUP_INTERVAL_MS = Math.max(10_000, Number(process.env.SIGNED_IPA_CLEANUP_INTERVAL_MS) || 10_000);
const MAX_CONCURRENT_JOBS = Math.max(1, Number(process.env.MAX_CONCURRENT_JOBS || 1));
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || '';
const JOB_ENCRYPTION_KEY = process.env.JOB_ENCRYPTION_KEY || '';
const REDIS_URL = String(process.env.REDIS_URL || '').trim();
const SHARED_QUEUE_ENABLED = Boolean(REDIS_URL);
const WORKER_ONLY = String(process.env.RUN_SIGNING_WORKER || '').toLowerCase() === 'true';
const QUEUE_NAME = 'xsigner-signing';
if (WORKER_ONLY && !SHARED_QUEUE_ENABLED) throw new Error('RUN_SIGNING_WORKER=true requires REDIS_URL.');
if (SHARED_QUEUE_ENABLED && !['s3', 'tigris'].includes(String(process.env.MANIFEST_STORAGE || '').toLowerCase())) {
  throw new Error('REDIS_URL requires MANIFEST_STORAGE=s3 so API and worker instances share authoritative job metadata.');
}
const API_CLIENT_DEFAULT_LIMIT = Number.isSafeInteger(Number(process.env.API_CLIENT_DEFAULT_LIMIT)) && Number(process.env.API_CLIENT_DEFAULT_LIMIT) > 0 ? Number(process.env.API_CLIENT_DEFAULT_LIMIT) : 120;
const API_CLIENT_DEFAULT_WINDOW_MS = Number.isSafeInteger(Number(process.env.API_CLIENT_DEFAULT_WINDOW_MS)) && Number(process.env.API_CLIENT_DEFAULT_WINDOW_MS) >= 60_000 ? Number(process.env.API_CLIENT_DEFAULT_WINDOW_MS) : 900_000;
const API_SIGN_AUTHENTICATED_IP_LIMIT = Number.isSafeInteger(Number(process.env.API_SIGN_AUTHENTICATED_IP_LIMIT)) && Number(process.env.API_SIGN_AUTHENTICATED_IP_LIMIT) > 0 ? Number(process.env.API_SIGN_AUTHENTICATED_IP_LIMIT) : 300;
// Leave API_CLIENTS_JSON unset to preserve the existing public Discord bot contract.
// When configured, X-API-Key authentication is required on signing submissions.
const API_CLIENTS = loadApiClients(process.env.API_CLIENTS_JSON || '', {
  defaultLimit: API_CLIENT_DEFAULT_LIMIT,
  defaultWindowMs: API_CLIENT_DEFAULT_WINDOW_MS
});
const apiClientQuotaWindows = new Map();
const execFileAsync = promisify(execFile);
const API_SIGN_FILE_LIMITS = {
  ipa: MAX_IPA_BYTES,
  p12: MAX_SMALL_FILE_BYTES,
  certificate: MAX_SMALL_FILE_BYTES, // Discord bot compatibility alias for p12
  mobileprovision: MAX_SMALL_FILE_BYTES,
  profile: MAX_SMALL_FILE_BYTES, // Discord bot compatibility alias for mobileprovision
  icon: MAX_SMALL_FILE_BYTES,
  deb: 256 * 1024 * 1024,
  dylib: 128 * 1024 * 1024,
  tweaks: 256 * 1024 * 1024 // Legacy bot field; extension validation happens in fileFilter
};
const apiSignStorage = {
  _handleFile(_req, file, callback) {
    const field = file.fieldname;
    const maxBytes = API_SIGN_FILE_LIMITS[field];
    if (!maxBytes) {
      file.stream.resume();
      return callback(Object.assign(new Error(`Unexpected file field: ${field}`), {status: 400}));
    }
    const filePath = path.join(WORK_ROOT, `discord-api-${crypto.randomUUID()}`);
    let size = 0;
    const limiter = new Transform({transform(chunk, _encoding, done) {
      size += chunk.length;
      if (size > maxBytes) return done(Object.assign(new Error(`${field} file exceeds the ${formatBytesSafe(maxBytes)} limit.`), {status: 413}));
      done(null, chunk);
    }});
    pipeline(file.stream, limiter, fs.createWriteStream(filePath, {flags: 'wx', mode: 0o600}))
      .then(() => callback(null, {path: filePath, filename: path.basename(filePath), size}))
      .catch(error => { void fsp.rm(filePath, {force: true}).finally(() => callback(error)); });
  },
  _removeFile(_req, file, callback) {
    fsp.rm(file.path, {force: true}).then(() => callback(null), callback);
  }
};
const apiSignUpload = multer({
  storage: apiSignStorage,
  limits: {fileSize: MAX_IPA_BYTES, files: 8, fields: 12, parts: 24, fieldNameSize: 64, fieldSize: 4096},
  fileFilter(_req, file, callback) {
    const ext = path.extname(file.originalname || '').toLowerCase();
    const allowed = {
      ipa: ['.ipa'], p12: ['.p12', '.pfx'], certificate: ['.p12', '.pfx'],
      mobileprovision: ['.mobileprovision'], profile: ['.mobileprovision'],
      icon: ['.png'], deb: ['.deb'], dylib: ['.dylib'], tweaks: ['.deb', '.dylib']
    };
    if (!allowed[file.fieldname] || !allowed[file.fieldname].includes(ext)) {
      return callback(Object.assign(new Error(`Invalid file type for ${file.fieldname}.`), {status: 400}));
    }
    callback(null, true);
  }
}).fields([
  {name: 'ipa', maxCount: 1}, {name: 'p12', maxCount: 1}, {name: 'certificate', maxCount: 1},
  {name: 'mobileprovision', maxCount: 1}, {name: 'profile', maxCount: 1},
  {name: 'icon', maxCount: 1}, {name: 'deb', maxCount: 1}, {name: 'dylib', maxCount: 1}, {name: 'tweaks', maxCount: 2}
]);
function handleApiSignUpload(req, res, next) {
  apiSignUpload(req, res, error => {
    if (!error) return next();
    const status = Number(error.status) || (error.code === 'LIMIT_FILE_SIZE' ? 413 : 400);
    return res.status(status).json({success: false, ok: false, error: messageOf(error)});
  });
}

await fsp.mkdir(WORK_ROOT, {recursive: true});
await fsp.mkdir(MANIFEST_ROOT, {recursive: true, mode: 0o700});

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy: false, crossOriginEmbedderPolicy: false}));
app.use((req, res, next) => {
  // Always generate a server-controlled correlation ID; never trust an arbitrary inbound value.
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.requestId);
  const originalJson = res.json.bind(res);
  res.json = payload => {
    let body = payload;
    if (body && typeof body === 'object' && !Array.isArray(body) && !Buffer.isBuffer(body)) {
      if (res.statusCode >= 400) {
        const messages = {
          400: ['BAD_REQUEST', 'The request is invalid.'], 401: ['UNAUTHORIZED', 'Authentication is required.'],
          403: ['FORBIDDEN', 'This request is not allowed.'], 404: ['NOT_FOUND', 'The requested resource was not found.'],
          409: ['CONFLICT', 'The request conflicts with the current job state.'], 410: ['RESULT_EXPIRED', 'The requested result has expired.'],
          413: ['PAYLOAD_TOO_LARGE', 'The uploaded payload exceeds the allowed limit.'], 415: ['UNSUPPORTED_MEDIA_TYPE', 'The content type is not supported.'],
          422: ['VALIDATION_ERROR', 'The request could not be processed.'], 429: ['RATE_LIMITED', 'Too many requests. Retry later.'],
          500: ['INTERNAL_ERROR', 'An unexpected server error occurred.'], 502: ['UPSTREAM_ERROR', 'A required upstream service failed.'],
          503: ['SERVICE_UNAVAILABLE', 'The service is temporarily unavailable.']
        };
        const [defaultCode, defaultMessage] = messages[res.statusCode] || ['HTTP_ERROR', `HTTP ${res.statusCode} request failed.`];
        body = {
          ...body, success: false, ok: false,
          error: typeof body.error === 'string' && body.error ? body.error : defaultMessage,
          code: typeof body.code === 'string' && body.code ? body.code : defaultCode,
          requestId: req.requestId
        };
      } else {
        body = {...body, requestId: body.requestId || req.requestId};
      }
    }
    return originalJson(body);
  };
  next();
});
app.use(express.json({limit: '1mb'}));
const actionLimiter = rateLimit({windowMs: 60_000, limit: 15, standardHeaders: 'draft-8', legacyHeaders: false, message: {success: false, ok: false, error: 'Too many requests. Try again shortly.'}});
const pollLimiter = rateLimit({windowMs: 60_000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false, message: {success: false, ok: false, error: 'Too many status requests. Slow down briefly.'}});

let s3Client;
function normalizeIp(value) {
  let candidate = String(value ?? '').trim();
  if (!candidate || candidate.includes(',')) return '';
  candidate = candidate.replace(/^::ffff:/i, '').split('%')[0];
  return net.isIP(candidate) ? candidate.toLowerCase() : '';
}
// Documentation is private to the configured owner IP. The signing API remains public.
const OWNER_IP = normalizeIp(process.env.OWNER_IP || process.env.XSIGNER_OWNER_IP || '168.91.23.165');
function normalizedClientIp(req) {
  // Render's public edge supplies CF-Connecting-IP. Do not trust caller-provided X-Forwarded-For.
  const edgeHeader = req.headers?.['cf-connecting-ip'];
  if (edgeHeader !== undefined) return normalizeIp(Array.isArray(edgeHeader) ? '' : edgeHeader);
  // In production, fail closed if the edge header is absent; local development may use the socket.
  if (process.env.NODE_ENV !== 'production') return normalizeIp(req.socket?.remoteAddress || req.ip);
  return '';
}
function isOwnerRequest(req) {
  const clientIp = normalizedClientIp(req);
  return Boolean(OWNER_IP && clientIp && clientIp === OWNER_IP);
}
function requireOwnerDocs(req, res, next) {
  if (!isOwnerRequest(req)) return res.status(404).set('Cache-Control', 'private, no-store').type('text').send('Not found');
  res.set('Cache-Control', 'private, no-store');
  next();
}
// Hot manifest cache: polling must not download manifest.json from object storage on every browser poll.
// S3-compatible storage is durable; cached metadata is only process memory.
const manifestCache = new Map();
function storageConfigured() {
  return Boolean(BUCKET && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY && ENDPOINT && REGION);
}
function getS3() {
  if (!storageConfigured()) throw new Error('Tigris storage is not configured. Set S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_ENDPOINT_URL_S3, and AWS_REGION in Render.');
  if (!s3Client) {
    s3Client = new S3Client({
      region: REGION,
      endpoint: ENDPOINT,
      // Tigris expects virtual-host-style bucket URLs for correctly signed requests.
      forcePathStyle: false,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      },
      maxAttempts: 4
    });
  }
  return s3Client;
}
function s3KeyForManifest(id) { return `jobs/${id}/manifest.json`; }
function isLocalManifestStorage() { return !['s3', 'tigris'].includes(String(process.env.MANIFEST_STORAGE || '').toLowerCase()); }

function redisConnectionOptions({worker = false} = {}) {
  const url = new URL(REDIS_URL);
  if (!['redis:', 'rediss:'].includes(url.protocol)) throw new Error('REDIS_URL must use redis:// or rediss://.');
  const database = url.pathname && url.pathname !== '/' ? Number(url.pathname.slice(1)) : 0;
  if (!Number.isSafeInteger(database) || database < 0) throw new Error('REDIS_URL database path must be a non-negative integer.');
  return {
    host: url.hostname, port: Number(url.port || 6379),
    ...(url.username ? {username: decodeURIComponent(url.username)} : {}),
    ...(url.password ? {password: decodeURIComponent(url.password)} : {}),
    db: database, maxRetriesPerRequest: worker ? null : 1, enableReadyCheck: true,
    connectTimeout: 10_000,
    ...(url.protocol === 'rediss:' ? {tls: {servername: url.hostname}} : {})
  };
}
const apiQuotaRedis = SHARED_QUEUE_ENABLED && !WORKER_ONLY
  ? new IORedis(REDIS_URL, {maxRetriesPerRequest: 1, enableReadyCheck: true, connectTimeout: 10_000})
  : null;
const signingQueue = SHARED_QUEUE_ENABLED
  ? new Queue(QUEUE_NAME, {connection: redisConnectionOptions({worker: false}), defaultJobOptions: {attempts: 1, removeOnComplete: true, removeOnFail: 1000}})
  : null;
if (apiQuotaRedis) apiQuotaRedis.on('error', error => console.error(JSON.stringify({event: 'client_quota_redis_error', message: safeTerminalLine(messageOf(error)).slice(0, 250)})));
if (signingQueue) signingQueue.on('error', error => console.error(JSON.stringify({event: 'signing_queue_connection_error', message: safeTerminalLine(messageOf(error)).slice(0, 250)})));
const apiDiagnosticCacheMs = Math.max(5_000, Number(process.env.HEALTH_DIAGNOSTIC_CACHE_MS || 15_000));
let apiDiagnosticCache = {checkedAt: 0, body: null};
function newId() { return crypto.randomUUID(); }
function hashToken(value) { return crypto.createHash('sha256').update(value).digest(); }
function tokenMatches(given, expectedHex) {
  if (typeof given !== 'string' || !expectedHex) return false;
  const a = hashToken(given);
  let b;
  try { b = Buffer.from(expectedHex, 'hex'); } catch { return false; }
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function encryptionKey() {
  if (!JOB_ENCRYPTION_KEY) throw new Error('JOB_ENCRYPTION_KEY is not configured on the server.');
  return crypto.createHash('sha256').update(JOB_ENCRYPTION_KEY).digest();
}
function encryptPassword(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return {iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: ciphertext.toString('base64')};
}
function decryptPassword(data) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(data.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(data.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(data.data, 'base64')), decipher.final()]).toString('utf8');
}
function validateId(id) { return typeof id === 'string' && /^[0-9a-f-]{36}$/i.test(id); }
function clampText(value, max) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function formatBytesSafe(bytes) { const n = Math.max(0, Number(bytes) || 0); if (n < 1024) return `${n} B`; if (n < 1024 ** 2) return `${(n/1024).toFixed(1)} KB`; if (n < 1024 ** 3) return `${(n/1024**2).toFixed(1)} MB`; return `${(n/1024**3).toFixed(2)} GB`; }
function messageOf(error) { return String(error?.message || 'Unexpected error').slice(0, 700); }
function storageErrorForUser(_error) { return 'Object storage is temporarily unavailable. Please retry shortly.'; }
function isManifestKey(key) { return typeof key === 'string' && key.startsWith('jobs/') && key.endsWith('/manifest.json'); }

function localManifestPath(id) { return path.join(MANIFEST_ROOT, `${id}.json`); }
async function persistManifestLocally(manifest) {
  const target = localManifestPath(manifest.id);
  const temporary = `${target}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    await fsp.writeFile(temporary, JSON.stringify(manifest), {mode: 0o600, flag: 'wx'});
    await fsp.rename(temporary, target);
  } catch (error) {
    await fsp.rm(temporary, {force: true}).catch(() => {});
    throw error;
  }
}
async function putManifest(manifest) {
  // Job metadata uses Render's persistent disk by default to reduce object-storage requests.
  // Set MANIFEST_STORAGE=s3 if you explicitly want manifests in Tigris instead.
  manifest.updatedAt = Date.now();
  if (!isLocalManifestStorage()) await getS3().send(new PutObjectCommand({
    Bucket: BUCKET, Key: s3KeyForManifest(manifest.id),
    Body: JSON.stringify(manifest), ContentType: 'application/json; charset=utf-8',
    CacheControl: 'no-store'
  }));
  await persistManifestLocally(manifest);
  manifestCache.set(manifest.id, manifest);
  while (manifestCache.size > 1500) manifestCache.delete(manifestCache.keys().next().value);
}
async function getManifest(id) {
  // In shared mode, object storage is authoritative: never return this instance's stale local cache.
  if (isLocalManifestStorage()) {
    const cached = manifestCache.get(id);
    if (cached) return cached;
    try {
      const body = await fsp.readFile(localManifestPath(id), 'utf8');
      const manifest = JSON.parse(body);
      manifestCache.set(id, manifest);
      return manifest;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    throw Object.assign(new Error('Job not found in local metadata store.'), {code: 'ENOENT'});
  }

  const response = await getS3().send(new GetObjectCommand({Bucket: BUCKET, Key: s3KeyForManifest(id)}));
  const body = await response.Body.transformToString();
  const manifest = JSON.parse(body);
  await persistManifestLocally(manifest);
  if (!SHARED_QUEUE_ENABLED) manifestCache.set(id, manifest);
  return manifest;
}
async function maybeManifest(id) {
  if (isLocalManifestStorage()) {
    const cached = manifestCache.get(id);
    if (cached) return cached;
  }
  try { return await getManifest(id); }
  catch (error) {
    if (error?.code === 'ENOENT' || error?.$metadata?.httpStatusCode === 404 || error?.name === 'NoSuchKey' || error?.name === 'NotFound') return null;
    throw error;
  }
}

async function authorizedJob(req, res, id) {
  if (!validateId(id)) { res.status(400).json({error: 'Invalid job ID.'}); return null; }
  const header = String(req.headers.authorization || '');
  const bearerMatch = /^Bearer\s+(.+)$/i.exec(header);
  const token = bearerMatch ? bearerMatch[1].trim() : '';
  try {
    const manifest = await maybeManifest(id);
    const jobTokenValid = Boolean(manifest && tokenMatches(token, manifest.tokenHash));
    const callerTokenValid = Boolean(manifest && manifest.source === 'api' && manifest.clientPollTokenHash && tokenMatches(token, manifest.clientPollTokenHash));
    if (!manifest || (!jobTokenValid && !callerTokenValid)) {
      res.status(404).json({error: 'Job not found or access token invalid.'});
      return null;
    }
    // On-demand recovery avoids a full object-storage scan at startup. This is especially
    // useful on one-instance Render services where in-memory queue state resets.
    if (!SHARED_QUEUE_ENABLED && !activeIds.has(id) && !queuedIds.has(id)) {
      if (manifest.status === 'queued') await enqueue(id);
      else if (manifest.status === 'signing' && Date.now() - Number(manifest.updatedAt || 0) > STALE_JOB_MS) {
        manifest.status = 'queued'; manifest.phase = 'queued'; manifest.progress = 64; manifest.error = null;
        appendJobLog(manifest, 'Recovered an interrupted signing job after its worker stopped.', 'system');
        await flushManifest(manifest);
        await enqueue(id);
      }
    }
    return manifest;
  } catch (error) {
    console.error(JSON.stringify({event: 'tigris_manifest_read_failed', requestId: req.requestId || null, jobId: id, message: safeTerminalLine(messageOf(error)).slice(0, 300), code: error?.Code || error?.code || null, status: error?.$metadata?.httpStatusCode || null}));
    res.status(503).json({error: storageErrorForUser(error)});
    return null;
  }
}
async function listManifestKeys() {
  // Local manifests are authoritative in local mode; do not list or download remote manifest history.
  const entries = await fsp.readdir(MANIFEST_ROOT, {withFileTypes: true});
  const localKeys = entries.filter(entry => entry.isFile() && /^[0-9a-f-]{36}\.json$/i.test(entry.name))
    .map(entry => `jobs/${entry.name.slice(0, -5)}/manifest.json`);
  if (isLocalManifestStorage() || (!SHARED_QUEUE_ENABLED && process.env.S3_RECOVER_ON_START !== 'true')) return localKeys;
  const keys = new Set(localKeys);
  const client = getS3();
  let token;
  do {
    const page = await client.send(new ListObjectsV2Command({Bucket: BUCKET, Prefix: 'jobs/', ContinuationToken: token, MaxKeys: 1000}));
    for (const obj of page.Contents || []) if (isManifestKey(obj.Key)) keys.add(obj.Key);
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
  return [...keys];
}
async function removeObject(key) {
  if (!key) return;
  try { await getS3().send(new DeleteObjectCommand({Bucket: BUCKET, Key: key})); }
  catch (error) { console.warn(JSON.stringify({event: 'tigris_object_cleanup_failed', keyPrefix: String(key).split('/').slice(0, 2).join('/'), code: error?.Code || error?.code || null, status: error?.$metadata?.httpStatusCode || null, message: safeTerminalLine(messageOf(error)).slice(0, 250)})); }
}
async function expireSignedResultIfNeeded(manifest) {
  if (!manifest || manifest.status !== 'completed' || !manifest.resultKey) return Boolean(manifest?.resultDeletedAt);
  const completedAt = Number(manifest.completedAt || manifest.updatedAt || 0);
  const expiresAt = Number(manifest.resultExpiresAt || (completedAt + SIGNED_IPA_RETENTION_MS));
  if (!expiresAt || Date.now() < expiresAt) return false;
  const expiredKey = manifest.resultKey;
  try {
    // Tigris supports the S3 DeleteObject operation. Only mark the result deleted after the API succeeds.
    await getS3().send(new DeleteObjectCommand({Bucket: BUCKET, Key: expiredKey}));
  } catch (error) {
    console.warn(JSON.stringify({event: 'tigris_signed_result_expiry_delete_failed', jobId: manifest.id, code: error?.Code || error?.code || null, status: error?.$metadata?.httpStatusCode || null, message: safeTerminalLine(messageOf(error)).slice(0, 250)}));
    return false;
  }
  manifest.resultKey = null;
  manifest.resultDeletedAt = Date.now();
  manifest.resultExpiresAt = expiresAt;
  appendJobLog(manifest, `The signed IPA was automatically deleted from Tigris after ${SIGNED_IPA_RETENTION_MINUTES} minutes.`, 'system');
  await flushManifest(manifest).catch(error => console.warn(JSON.stringify({event: 'tigris_expiry_manifest_persist_failed', jobId: manifest.id, message: safeTerminalLine(messageOf(error)).slice(0, 250)})));
  return true;
}
async function cleanupInputs(manifest, abortOpen = true) {
  const client = getS3();
  for (const upload of Object.values(manifest.uploads || {})) {
    if (!upload || !upload.key) continue;
    if (abortOpen && upload.uploadId && !upload.completed) {
      try { await client.send(new AbortMultipartUploadCommand({Bucket: BUCKET, Key: upload.key, UploadId: upload.uploadId})); }
      catch (error) { /* The multipart upload may already have expired or completed. */ }
    }
    await removeObject(upload.key);
    upload.uploadId = null;
  }
}

function ipv6Words(address) {
  let value = String(address || '').toLowerCase();
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const v4 = value.slice(lastColon + 1);
    const octets = v4.split('.').map(Number);
    if (octets.length !== 4 || octets.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    value = `${value.slice(0, lastColon + 1)}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right].map(part => /^[0-9a-f]{1,4}$/.test(part) ? Number.parseInt(part, 16) : NaN);
  return words.length === 8 && words.every(Number.isInteger) ? words : null;
}
function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a,b,c,d] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || (b === 168) || (b === 88 && c === 99) || (b === 31 && c === 196) || (b === 52 && c === 193) || (b === 175 && c === 48))) ||
      (a === 198 && ((b === 18 || b === 19) || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113) ||
      (a === 255 && b === 255 && c === 255 && d === 255);
  }
  if (family === 6) {
    const words = ipv6Words(address);
    if (!words) return true;
    const first = words[0], second = words[1];
    // Only globally routable unicast space (2000::/3) is eligible for remote downloads.
    if ((first & 0xe000) !== 0x2000) return true;
    if (first === 0x2001 && (second <= 0x01ff || second === 0x0db8)) return true; // IANA special-purpose 2001::/23 includes Teredo, benchmarking and documentation ranges.
    if (first === 0x2002) return true; // 6to4 embeds an IPv4 destination.
    return false;
  }
  return true;
}
async function resolvePublicHttpsUrl(raw) {
  let url;
  try { url = new URL(String(raw || '').trim()); } catch { throw new Error('URL is invalid.'); }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname || (url.port && url.port !== '443')) {
    throw new Error('URL must be a public HTTPS URL without embedded credentials or a non-standard port.');
  }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('Private or local URLs are not allowed.');
  }
  let addresses;
  const literalFamily = net.isIP(hostname);
  if (literalFamily) addresses = [{address: hostname, family: literalFamily}];
  else {
    try { addresses = await dns.lookup(hostname, {all: true, verbatim: true}); }
    catch { throw new Error('Could not resolve the URL hostname.'); }
  }
  if (!addresses.length || addresses.some(item => isPrivateAddress(item.address))) {
    throw new Error('URL must resolve only to globally routable public IP addresses.');
  }
  url.hash = '';
  return {url: url.toString(), hostname, addresses: addresses.map(item => ({address: item.address, family: item.family || net.isIP(item.address)}))};
}
async function validatePublicHttpsUrl(raw) {
  return (await resolvePublicHttpsUrl(raw)).url;
}
async function requestPinnedHttps(target, headers, timeoutSignal) {
  const expectedHost = target.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  return new Promise((resolve, reject) => {
    const req = https.request(new URL(target.url), {
      method: 'GET', headers, signal: timeoutSignal, autoSelectFamily: true,
      ...(net.isIP(expectedHost) ? {} : {servername: expectedHost}),
      lookup(hostname, options, callback) {
        const normalized = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
        if (normalized !== expectedHost) return callback(new Error('Outbound lookup hostname changed after validation.'));
        if (options?.all) return callback(null, target.addresses);
        const first = target.addresses[0];
        return callback(null, first.address, first.family || net.isIP(first.address));
      }
    }, resolve);
    req.on('error', reject);
    req.end();
  });
}

function remoteFilename(urlString, kind, requestedName = '') {
  const fallback = {ipa: 'remote-app.ipa', certificate: 'certificate.p12', profile: 'profile.mobileprovision'}[kind] || `remote-${kind}`;
  const isAllowed = name => {
    const ext = path.extname(name).toLowerCase();
    return (kind === 'ipa' && ext === '.ipa') || (kind === 'certificate' && ['.p12','.pfx'].includes(ext)) || (kind === 'profile' && ext === '.mobileprovision');
  };
  const requested = path.basename(clampText(requestedName, 240));
  if (requested && !requested.includes('\0') && isAllowed(requested)) return requested;
  try {
    const url = new URL(urlString);
    const candidate = decodeURIComponent(path.basename(url.pathname));
    if (candidate && !candidate.includes('\0') && isAllowed(candidate)) return candidate;
  } catch {}
  return fallback;
}
function makeRemoteUpload(kind, sourceUrl, requestedName = '') {
  const maxBytes = ({ipa: MAX_IPA_BYTES, certificate: MAX_SMALL_FILE_BYTES, profile: MAX_SMALL_FILE_BYTES})[kind];
  return {key: null, uploadId: null, filename: remoteFilename(sourceUrl, kind, requestedName), contentType: 'application/octet-stream', expectedSize: null, partCount: 0, completed: true, actualSize: null, remote: true, sourceUrl, maxBytes};
}
async function downloadRemoteToFile(rawUrl, destination, maxBytes, onProgress = () => {}) {
  let currentUrl = rawUrl;
  const configuredTimeout = Number(process.env.REMOTE_FETCH_TIMEOUT_MS || 60 * 60 * 1000);
  const timeoutMs = Number.isFinite(configuredTimeout) && configuredTimeout >= 60_000 ? configuredTimeout : 60 * 60 * 1000;
  const userAgent = String(process.env.REMOTE_FETCH_USER_AGENT || 'xsigner-ipa-signer/2.1 (+https://xsigner.onrender.com)')
    .replace(/[\r\n]/g, '').slice(0, 200);
  const requestHeaders = {
    'user-agent': userAgent,
    'accept': 'application/octet-stream, application/zip, */*',
    // Avoid transparent compression changing the byte count for multi-gigabyte ZIP files.
    'accept-encoding': 'identity'
  };
  if (process.env.REMOTE_FETCH_REFERER) {
    let referer;
    try { referer = new URL(process.env.REMOTE_FETCH_REFERER); } catch { throw new Error('REMOTE_FETCH_REFERER must be a valid HTTPS URL.'); }
    if (referer.protocol !== 'https:') throw new Error('REMOTE_FETCH_REFERER must be a valid HTTPS URL.');
    requestHeaders.referer = referer.toString();
  }

  for (let redirects = 0; redirects <= 5; redirects++) {
    const validatedTarget = await resolvePublicHttpsUrl(currentUrl);
    currentUrl = validatedTarget.url;
    const sourceHost = validatedTarget.hostname;
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    let response;
    try {
      response = await requestPinnedHttps(validatedTarget, requestHeaders, timeoutSignal);
    } catch (error) {
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError' || timeoutSignal.aborted) {
        throw new Error(`Remote IPA download from ${sourceHost} timed out after ${Math.round(timeoutMs / 60000)} minutes. Increase REMOTE_FETCH_TIMEOUT_MS or use a faster direct-download host.`);
      }
      throw new Error(`Could not connect to remote file host ${sourceHost}: ${messageOf(error)}`);
    }

    if ([301,302,303,307,308].includes(response.statusCode)) {
      const location = response.headers.location;
      response.destroy();
      if (!location || redirects === 5) throw new Error(`Remote file URL on ${sourceHost} redirected too many times.`);
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }
    if (response.statusCode === 401 || response.statusCode === 403) {
      response.destroy();
      throw new Error(
        `Remote file host ${sourceHost} refused the download (HTTP ${response.statusCode}). This is a source-host access restriction, not the IPA size limit. Use a direct public HTTPS download URL that works without login, cookies, CAPTCHA, or hotlink authorization. If you control the host, allowlist xsigner or set REMOTE_FETCH_USER_AGENT / REMOTE_FETCH_REFERER to the host's documented requirements.`
      );
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      response.destroy();
      const hint = response.statusCode === 404 ? ' Check that the link points to the actual IPA file and has not expired.' : '';
      throw new Error(`Remote file host ${sourceHost} returned HTTP ${response.statusCode}.${hint}`);
    }

    const contentLengthHeader = response.headers['content-length'];
    const parsedLength = contentLengthHeader ? Number(contentLengthHeader) : 0;
    const declared = Number.isFinite(parsedLength) && parsedLength > 0 ? parsedLength : 0;
    if (declared > maxBytes) {
      response.destroy();
      throw new Error(`Remote IPA from ${sourceHost} is ${formatBytesSafe(declared)}, exceeding the configured ${formatBytesSafe(maxBytes)} IPA limit.`);
    }

    let received = 0;
    const partPath = `${destination}.part`;
    await fsp.rm(partPath, {force: true}).catch(() => {});
    const counter = new Transform({transform(chunk, _encoding, callback) {
      received += chunk.length;
      if (received > maxBytes) return callback(new Error(`Remote IPA exceeded the configured ${formatBytesSafe(maxBytes)} limit while downloading.`));
      onProgress(received, declared || null);
      callback(null, chunk);
    }});
    try {
      await pipeline(response, counter, fs.createWriteStream(partPath, {flags: 'wx', mode: 0o600}));
      if (declared && received !== declared) throw new Error(`Remote file download from ${sourceHost} ended at ${formatBytesSafe(received)} of the declared ${formatBytesSafe(declared)}.`);
      if (received < 1) throw new Error(`Remote file host ${sourceHost} returned an empty file.`);
      await fsp.rename(partPath, destination);
      return received;
    } catch (error) {
      await fsp.rm(partPath, {force: true}).catch(() => {});
      if (timeoutSignal.aborted || error?.name === 'TimeoutError' || error?.name === 'AbortError') {
        throw new Error(`Remote IPA download from ${sourceHost} timed out after ${Math.round(timeoutMs / 60000)} minutes (received ${formatBytesSafe(received)}). Increase REMOTE_FETCH_TIMEOUT_MS or use a faster direct-download host.`);
      }
      throw error;
    }
  }
  throw new Error('Remote file URL could not be fetched.');
}
app.get(['/healthz', '/health'], (_req, res) => {
  const signerPresent = fs.existsSync(SIGNER);
  const storageReady = storageConfigured();
  const encryptionReady = Boolean(JOB_ENCRYPTION_KEY);
  const ready = signerPresent && storageReady && encryptionReady;
  return res.status(ready ? 200 : 503).json({
    ok: ready,
    status: ready ? 'ok' : 'degraded',
    service: 'xsigner',
    signer: 'zsign',
    signerPresent,
    storageConfigured: storageReady,
    encryptionConfigured: encryptionReady
  });
});
app.get('/healthz/dependencies', async (_req, res) => {
  const now = Date.now();
  if (!apiDiagnosticCache.body || now - apiDiagnosticCache.checkedAt >= apiDiagnosticCacheMs) {
    const checks = {signer: false, storage: false, encryption: Boolean(JOB_ENCRYPTION_KEY), workDirectory: false, redisQueue: !SHARED_QUEUE_ENABLED};
    const failures = [];
    try {
      await fsp.access(SIGNER, fs.constants.X_OK);
      const version = await execFileAsync(SIGNER, ['-v'], {encoding: 'utf8', timeout: 2500, maxBuffer: 64 * 1024});
      checks.signer = Number.isInteger(version?.code) ? version.code === 0 : true;
    } catch (error) { failures.push('signer'); }
    try {
      await fsp.access(WORK_ROOT, fs.constants.W_OK);
      checks.workDirectory = true;
    } catch { failures.push('workDirectory'); }
    if (storageConfigured()) {
      try {
        await getS3().send(new HeadBucketCommand({Bucket: BUCKET}), {abortSignal: AbortSignal.timeout(2500)});
        checks.storage = true;
      } catch { failures.push('storage'); }
    } else failures.push('storage');
    if (SHARED_QUEUE_ENABLED) {
      try { checks.redisQueue = (await apiQuotaRedis?.ping()) === 'PONG' || WORKER_ONLY; }
      catch { failures.push('redisQueue'); }
    }
    if (!checks.encryption) failures.push('encryption');
    const names = Object.keys(checks);
    const ready = failures.length === 0 && names.every(name => checks[name]);
    apiDiagnosticCache = {
      checkedAt: now,
      body: {ok: ready, status: ready ? 'ok' : 'degraded', service: 'xsigner', checks, checkedAt: new Date(now).toISOString(), cacheMs: apiDiagnosticCacheMs}
    };
  }
  const body = apiDiagnosticCache.body;
  return res.status(body.ok ? 200 : 503).set('Cache-Control', 'no-store').json(body);
});

// Operational metrics are restricted to the configured owner IP and expose no secrets.
// Disk metrics are informational only; no admission limits or rejection thresholds are applied here.
app.get('/api/ops/metrics', requireOwnerDocs, async (_req, res) => {
  try {
    const queue = {
      mode: SHARED_QUEUE_ENABLED ? 'bullmq' : 'in-process',
      waiting: SHARED_QUEUE_ENABLED ? 0 : pendingQueue.length,
      active: SHARED_QUEUE_ENABLED ? 0 : activeIds.size,
      configuredConcurrency: MAX_CONCURRENT_JOBS,
      workerOnly: WORKER_ONLY
    };
    if (signingQueue) {
      const counts = await signingQueue.getJobCounts('waiting', 'active', 'delayed', 'completed', 'failed', 'waiting-children', 'prioritized');
      Object.assign(queue, counts);
    }
    let disk = {availableBytes: null, totalBytes: null, usedPercent: null, status: 'unavailable'};
    try {
      const stat = await fsp.statfs(ROOT);
      const blockSize = Number(stat.bsize || stat.frsize || 0);
      const totalBytes = Number(stat.blocks) * blockSize;
      const availableBytes = Number(stat.bavail) * blockSize;
      disk = {
        availableBytes: Number.isFinite(availableBytes) ? availableBytes : null,
        totalBytes: Number.isFinite(totalBytes) ? totalBytes : null,
        usedPercent: totalBytes > 0 ? Math.round((1 - availableBytes / totalBytes) * 1000) / 10 : null,
        status: 'ok'
      };
    } catch (error) {
      console.warn(JSON.stringify({event: 'disk_metrics_unavailable', message: safeTerminalLine(messageOf(error)).slice(0, 200)}));
    }
    return res.set('Cache-Control', 'private, no-store').json({
      ok: true,
      service: 'xsigner',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      queue,
      disk,
      results: {retentionMinutes: SIGNED_IPA_RETENTION_MINUTES},
      runtime: {node: process.version, platform: process.platform, arch: process.arch}
    });
  } catch (error) {
    console.error(JSON.stringify({event: 'operational_metrics_failed', requestId: _req.requestId || null, message: safeTerminalLine(messageOf(error)).slice(0, 300)}));
    return res.status(503).json({success: false, ok: false, code: 'METRICS_UNAVAILABLE', error: 'Operational metrics are temporarily unavailable.'});
  }
});

app.get('/', (_req, res) => res.set('Cache-Control', 'no-store').json({
  service: 'xsigner-signing-api',
  status: 'ok',
  signingEngine: 'zsign',
  documentation: '/doc (owner IP only)',
  endpoints: {
    sign: {method: 'POST', path: '/sign', contentType: 'multipart/form-data'},
    discordCompatibility: {method: 'POST', path: '/api/v1/discord/sign'},
    health: {method: 'GET', path: '/api/v1/discord/health'},
    renderHealth: {method: 'GET', path: '/healthz'},
    dependencyHealth: {method: 'GET', path: '/healthz/dependencies'},
    ownerMetrics: {method: 'GET', path: '/api/ops/metrics'},
    jobStatus: {method: 'GET', path: '/api/jobs/{jobId}?after=0'},
    downloadUrl: {method: 'POST', path: '/api/jobs/{jobId}/download-url'},
    otaUrl: {method: 'POST', path: '/api/jobs/{jobId}/ota-url'}
  },
  ipaInput: 'Upload ipa as a file OR supply ipaUrl as the only URL field. p12 and mobileprovision must be uploaded files.'
}));
app.get('/sign', (_req, res) => res.status(405).set('Allow', 'POST').json({
  success: false, ok: false,
  error: 'Signing requires POST /sign with multipart/form-data. Use ipa as a file or ipaUrl as the only URL field, plus p12/certificate and mobileprovision/profile files.'
}));

app.get('/api/v1/discord/health', (_req, res) => {
  const signerPresent = fs.existsSync(SIGNER);
  const storageReady = storageConfigured();
  const encryptionReady = Boolean(JOB_ENCRYPTION_KEY);
  const ready = signerPresent && storageReady && encryptionReady;
  return res.status(ready ? 200 : 503).json({
    status: ready ? 'ok' : 'degraded', service: 'xsigner',
    dependencies: {signing_engine: signerPresent ? 'zsign' : 'missing', storage: storageReady ? 'tigris-configured' : 'unconfigured', job_encryption: encryptionReady ? 'configured' : 'unconfigured'},
    ...(ready ? {} : {error: 'Signing service is not fully configured. Check zsign, Tigris environment variables, and JOB_ENCRYPTION_KEY.'})
  });
});

const API_SIGN_RATE_LIMIT = Math.max(1, Number(process.env.API_SIGN_RATE_LIMIT || 30));
const publicSignLimiter = rateLimit({
  windowMs: 15 * 60_000, limit: API_SIGN_RATE_LIMIT, standardHeaders: 'draft-8', legacyHeaders: false,
  skip: req => Boolean(req.apiClient),
  message: {success: false, ok: false, error: 'Too many anonymous signing requests from this source IP. Retry later.', code: 'IP_RATE_LIMITED'}
});
const authenticatedSignIpLimiter = rateLimit({
  windowMs: 15 * 60_000, limit: API_SIGN_AUTHENTICATED_IP_LIMIT, standardHeaders: 'draft-8', legacyHeaders: false,
  skip: req => !req.apiClient,
  message: {success: false, ok: false, error: 'Too many authenticated signing requests from this source IP. Retry later.', code: 'AUTHENTICATED_IP_RATE_LIMITED'}
});
async function consumeConfiguredClientQuota(client) {
  if (!apiQuotaRedis) return consumeApiClientQuota(client, apiClientQuotaWindows);
  const now = Date.now();
  const windowNumber = Math.floor(now / client.windowMs);
  const resetAt = (windowNumber + 1) * client.windowMs;
  const key = `xsigner:client-quota:${client.id}:${windowNumber}`;
  const script = "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); end; return count";
  const count = Number(await apiQuotaRedis.eval(script, 1, key, String(client.windowMs + 5000)));
  return {
    allowed: count <= client.limit, limit: client.limit,
    remaining: Math.max(0, client.limit - count), resetAt,
    retryAfterSeconds: count <= client.limit ? 0 : Math.max(1, Math.ceil((resetAt - now) / 1000))
  };
}
async function authenticateApiClientAndApplyQuota(req, res, next) {
  // Backwards-compatible default: no API_CLIENTS_JSON means the old public /sign contract.
  if (API_CLIENTS.size === 0) return next();
  const client = resolveApiClient(req.get('x-api-key') || '', API_CLIENTS);
  if (!client) {
    return res.status(401).set('WWW-Authenticate', 'X-API-Key').set('Cache-Control', 'no-store').json({
      success: false, ok: false, code: 'API_KEY_REQUIRED',
      error: 'A valid X-API-Key header is required because per-client authentication is enabled.'
    });
  }
  let quota;
  try { quota = await consumeConfiguredClientQuota(client); }
  catch {
    return res.status(503).set('Cache-Control', 'no-store').json({
      success: false, ok: false, code: 'CLIENT_QUOTA_STORE_UNAVAILABLE',
      error: 'The client quota store is unavailable. Retry shortly.'
    });
  }
  req.apiClient = {id: client.id, limit: client.limit, windowMs: client.windowMs};
  res.set('X-API-Client', client.id);
  res.set('X-API-Client-Limit', String(quota.limit));
  res.set('X-API-Client-Remaining', String(quota.remaining));
  res.set('X-API-Client-Reset', String(Math.ceil(quota.resetAt / 1000)));
  if (!quota.allowed) {
    res.set('Retry-After', String(quota.retryAfterSeconds));
    return res.status(429).set('Cache-Control', 'no-store').json({
      success: false, ok: false, code: 'API_CLIENT_RATE_LIMITED',
      error: `API client quota exceeded. Retry in ${quota.retryAfterSeconds} seconds.`,
      limit: quota.limit, remaining: 0, retryAfterSeconds: quota.retryAfterSeconds
    });
  }
  return next();
}
app.post(['/sign', '/api/v1/discord/sign'], authenticateApiClientAndApplyQuota, publicSignLimiter, authenticatedSignIpLimiter, handleApiSignUpload, async (req, res) => {
  const body = req.body || {};
  const files = req.files || {};
  const file = field => Array.isArray(files[field]) ? files[field][0] : null;
  const ipaFile = file('ipa');
  const p12File = file('p12') || file('certificate');
  const profileFile = file('mobileprovision') || file('profile');
  const iconFile = file('icon');
  const legacyTweaks = Array.isArray(files.tweaks) ? files.tweaks : [];
  const debFile = file('deb') || legacyTweaks.find(item => path.extname(item.originalname || '').toLowerCase() === '.deb') || null;
  const dylibFile = file('dylib') || legacyTweaks.find(item => path.extname(item.originalname || '').toLowerCase() === '.dylib') || null;
  const localApiFiles = Object.values(files).flat().filter(Boolean);
  let manifest = null;
  let password = '';
  let submissionStage = 'validation';

  try {
    if (!storageConfigured()) return res.status(503).json({success: false, ok: false, error: 'Tigris storage is not configured.'});
    if (!JOB_ENCRYPTION_KEY) return res.status(503).json({success: false, ok: false, error: 'Signing job encryption is not configured.'});

    const rawIpaUrl = clampText(body.ipaUrl || body.ipa_url, 4096);
    // ipaUrl is the only URL accepted for source material. Certificates and profiles must be uploaded files.
    if (body.p12Url || body.p12_url || body.certificateUrl || body.mobileprovisionUrl || body.mobileprovision_url || body.profileUrl || body.profile_url) {
      return res.status(400).json({success: false, ok: false, error: 'Only ipaUrl may be provided as a URL. Upload p12 and mobileprovision as files.'});
    }
    if (ipaFile && rawIpaUrl) return res.status(400).json({success: false, ok: false, error: 'Provide either the ipa file or ipaUrl, not both.'});
    if (!ipaFile && !rawIpaUrl) return res.status(400).json({success: false, ok: false, error: 'Provide an ipa file or ipaUrl.'});
    if (!p12File || !profileFile) return res.status(400).json({success: false, ok: false, error: 'Upload the signing certificate as p12/certificate and the profile as mobileprovision/profile files.'});

    let ipaUrl = '';
    if (rawIpaUrl) {
      try { ipaUrl = await validatePublicHttpsUrl(rawIpaUrl); }
      catch (error) { throw Object.assign(new Error(`Invalid IPA URL: ${messageOf(error)}`, {cause: error}), {status: 400}); }
    }
    password = typeof body.password === 'string' ? body.password : '';
    if (password.length > 2048) return res.status(400).json({success: false, ok: false, error: 'P12 password is too long.'});
    const bundleId = clampText(body.bundleId || body.bundle_id, 200);
    if (bundleId && !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId)) return res.status(400).json({success: false, ok: false, error: 'Bundle ID format is invalid.'});
    const bundleName = clampText(body.appName || body.app_name || body.bundleName || body.bundle_name, 200);
    const bundleVersion = clampText(body.bundleVersion || body.bundle_version || body.version, 100);
    if (bundleVersion && !/^[A-Za-z0-9._+-]+$/.test(bundleVersion)) return res.status(400).json({success: false, ok: false, error: 'Version format is invalid.'});
    const requestedSigner = clampText(body.signer, 32).toLowerCase();
    if (requestedSigner && requestedSigner !== 'zsign') {
      return res.status(400).json({success: false, ok: false, error: 'This API runs zsign only. Select signer=zsign or omit the signer field.'});
    }
    const injectExtensions = body.injectExtensions === true || ['true', '1', 'yes'].includes(String(body.injectExtensions || '').trim().toLowerCase());

    const id = newId();
    const token = crypto.randomBytes(32).toString('base64url');
    const requestBearerMatch = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ''));
    const optionalCallerBearer = requestBearerMatch ? requestBearerMatch[1].trim() : '';
    // Public submission remains unauthenticated. If the provided Discord bot sends its
    // existing bearer, hash it onto this job for backward-compatible polling. This hash is
    // scoped to this one job; new clients should prefer the returned jobToken.
    const clientPollTokenHash = optionalCallerBearer.length > 0 ? hashToken(optionalCallerBearer).toString('hex') : null;
    const createdAt = Date.now();
    manifest = {
      id, tokenHash: hashToken(token).toString('hex'), clientPollTokenHash, source: 'api', status: 'creating_uploads', phase: 'preparing', progress: 0,
      requestId: req.requestId, createdAt, updatedAt: createdAt, queuedAt: null, startedAt: null, completedAt: null, attemptCount: 0, uploads: {},
      settings: {bundleId, bundleName, bundleVersion, injectExtensions},
      passwordCipher: encryptPassword(password), resultKey: null, resultSize: null, resultExpiresAt: null,
      error: null, logs: [], logSequence: 0, otaTokenHash: null, otaExpiresAt: null, otaMetadata: null
    };

    if (ipaUrl) {
      manifest.uploads.ipa = makeRemoteUpload('ipa', ipaUrl);
      appendJobLog(manifest, 'API request accepted. IPA will be fetched from the supplied public HTTPS URL.', 'system');
    }
    const uploadMap = [
      [p12File, 'certificate'], [profileFile, 'profile'], [iconFile, 'icon'], [debFile, 'deb'], [dylibFile, 'dylib'],
      ...(!ipaUrl && ipaFile ? [[ipaFile, 'ipa']] : [])
    ];
    submissionStage = ipaUrl ? 'remote_ipa_registration' : 'upload_inputs';
    for (const [source, kind] of uploadMap) {
      if (!source) continue;
      const extension = path.extname(source.originalname).toLowerCase();
      const key = `uploads/${id}/${kind}${extension}`;
      const contentType = source.mimetype || 'application/octet-stream';
      appendJobLog(manifest, `Uploading API ${kind} file to private Tigris storage (${formatBytesSafe(source.size)}).`, 'system');
      const uploader = new Upload({
        client: getS3(),
        params: {
          Bucket: BUCKET, Key: key, Body: fs.createReadStream(source.path), ContentLength: source.size,
          ContentType: contentType, Metadata: {jobid: id, kind, source: 'discord-api'}
        },
        queueSize: 2, partSize: Math.max(64 * 1024 * 1024, PART_SIZE), leavePartsOnError: false
      });
      await uploader.done();
      manifest.uploads[kind] = {
        key, uploadId: null, filename: path.basename(source.originalname).slice(0, 240),
        contentType, expectedSize: source.size, partCount: 0, completed: true, actualSize: source.size, remote: false
      };
    }
    if (!manifest.uploads.ipa) throw Object.assign(new Error('The IPA source was not provided.'), {status: 400});
    if (!manifest.uploads.certificate || !manifest.uploads.profile) throw Object.assign(new Error('The P12 and mobileprovision files must both be uploaded.'), {status: 400});
    submissionStage = 'queue_job';
    manifest.queuedAt = Date.now();
    manifest.status = 'queued'; manifest.phase = 'queued'; manifest.progress = 64;
    manifestCache.set(manifest.id, manifest);
    appendJobLog(manifest, API_CLIENTS.size ? 'Discord API signing request accepted with per-client authentication and quota limits.' : 'Discord API signing request accepted without API-key authentication; requests are rate-limited per IP.', 'system');
    await flushManifest(manifest);
    await enqueue(manifest.id);
    const origin = (PUBLIC_ORIGIN || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
    const statusUrl = `${origin}/api/jobs/${manifest.id}?after=0`;
    return res.status(202).set('Cache-Control', 'no-store').json({
      success: true, ok: true, jobId: manifest.id, job_id: manifest.id, jobToken: token,
      status: 'queued', stage: 'queued', progress: Number(manifest.progress || 0),
      message: 'Signing request accepted and queued for zsign.', poll_after_ms: 1000,
      statusUrl, status_url: statusUrl, progressUrl: statusUrl, progress_url: statusUrl,
      downloadUrlEndpoint: `${origin}/api/jobs/${manifest.id}/download-url`,
      otaUrlEndpoint: `${origin}/api/jobs/${manifest.id}/ota-url`
    });
  } catch (error) {
    console.error(JSON.stringify({
      event: 'signing_submission_failed', requestId: req.requestId || null, jobId: manifest?.id || null,
      stage: submissionStage, status: Number(error?.status) || 503,
      code: typeof error?.code === 'string' ? error.code.slice(0, 64) : null,
      message: safeTerminalLine(messageOf(error), password).slice(0, 400)
    }));
    if (manifest) {
      for (const upload of Object.values(manifest.uploads || {})) if (upload?.key) await removeObject(upload.key);
      if (manifest.resultKey) await removeObject(manifest.resultKey);
      if (!isLocalManifestStorage()) await removeObject(s3KeyForManifest(manifest.id));
      manifest.passwordCipher = null;
      await fsp.rm(localManifestPath(manifest.id), {force: true}).catch(() => {});
      manifestCache.delete(manifest.id);
    }
    if (!res.headersSent) return res.status(error?.status || 503).json({success: false, ok: false, error: error?.status ? messageOf(error) : 'Could not queue the signing request. Check object storage and encryption configuration.'});
  } finally {
    password = '';
    await Promise.all(localApiFiles.map(source => fsp.rm(source.path, {force: true}).catch(() => {})));
  }
});

async function buildApiCompletionResult(manifest, req) {
  const result = {
    appName: manifest.otaMetadata?.appName || manifest.settings?.bundleName || 'Signed app',
    bundleId: manifest.otaMetadata?.bundleId || manifest.settings?.bundleId || '',
    version: manifest.otaMetadata?.version || manifest.settings?.bundleVersion || '1.0',
    signingTime: `${Math.max(1, Math.round((Number(manifest.completedAt || Date.now()) - Number(manifest.createdAt || Date.now())) / 1000))}s`,
    resultExpiresAt: new Date(Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS))).toISOString(),
    resultExpiresAtMs: Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS))
  };
  await expireSignedResultIfNeeded(manifest);
  if (!manifest.resultKey) {
    result.error = 'The signed IPA has expired or is unavailable.';
    return result;
  }
  const expiresAt = Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS));
  const remainingSeconds = Math.floor((expiresAt - Date.now()) / 1000);
  if (remainingSeconds < 1) {
    result.error = 'The signed IPA has expired or is unavailable.';
    return result;
  }
  try {
    const downloadUrl = await getSignedUrl(getS3(), new GetObjectCommand({
      Bucket: BUCKET, Key: manifest.resultKey,
      ResponseContentDisposition: 'attachment; filename="signed.ipa"',
      ResponseContentType: 'application/octet-stream'
    }), {expiresIn: Math.max(1, Math.min(600, remainingSeconds))});
    result.downloadUrl = downloadUrl;
    result.download_url = downloadUrl;
  } catch (error) {
    console.warn('Discord API completion download URL failed:', messageOf(error));
  }
  if (!result.bundleId) {
    result.otaError = 'Could not determine the app Bundle ID. Supply bundleId to enable OTA installation.';
    return result;
  }
  try {
    const installToken = crypto.randomBytes(32).toString('base64url');
    manifest.otaTokenHash = hashToken(installToken).toString('hex');
    manifest.otaExpiresAt = Math.min(Date.now() + 24 * 60 * 60 * 1000, expiresAt);
    await putManifest(manifest);
    const origin = (PUBLIC_ORIGIN || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
    const manifestUrl = `${origin}/ota/${manifest.id}/${installToken}/manifest.plist`;
    const installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;
    result.manifestUrl = manifestUrl;
    result.installUrl = installUrl;
    result.otaUrl = installUrl;
    result.ota_url = installUrl;
  } catch (error) {
    console.warn('Discord API completion OTA URL failed:', messageOf(error));
    result.otaError = 'Could not create the OTA installation link.';
  }
  return result;
}

app.get('/api/jobs/:id', pollLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  const after = Math.max(0, Number.parseInt(req.query.after || '0', 10) || 0);
  const logs = (manifest.logs || []).filter(entry => Number(entry.id) > after).slice(-120);
  const response = {
    success: true, ok: true, id: manifest.id, jobId: manifest.id, job_id: manifest.id,
    status: manifest.status, phase: manifest.phase, stage: manifest.phase,
    progress: Number(manifest.progress || 0), poll_after_ms: manifest.status === 'completed' || manifest.status === 'failed' ? 0 : 1000,
    message: logs.length ? logs[logs.length - 1].message : (manifest.status === 'queued' ? 'Queued for zsign worker.' : 'Signing job is processing.'),
    error: manifest.status === 'failed' ? manifest.error : null,
    resultSize: manifest.status === 'completed' ? manifest.resultSize : null,
    appName: manifest.otaMetadata?.appName || manifest.settings?.bundleName || null,
    logSequence: Number(manifest.logSequence || 0), logs
  };
  if (manifest.status === 'completed' && manifest.source === 'api') {
    response.signingTime = `${Math.max(1, Math.round((Number(manifest.completedAt || Date.now()) - Number(manifest.createdAt || Date.now())) / 1000))}s`;
    response.resultExpiresAt = new Date(Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS))).toISOString();
    response.resultExpiresAtMs = Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS));
    response.result = await buildApiCompletionResult(manifest, req);
  }
  res.set('Cache-Control', 'no-store').json(response);
});

app.post('/api/jobs/:id/download-url', actionLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  if (manifest.status !== 'completed') return res.status(409).json({error: 'Signed IPA is not ready yet.'});
  await expireSignedResultIfNeeded(manifest);
  if (!manifest.resultKey) return res.status(410).json({error: `This signed IPA expired and was deleted after ${SIGNED_IPA_RETENTION_MINUTES} minutes. Sign the app again to create a new download.`});
  const remainingSeconds = Math.floor((Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS)) - Date.now()) / 1000);
  if (remainingSeconds < 1) return res.status(410).json({error: 'This signed IPA has expired. Sign the app again to create a new download.'});
  const expiresIn = Math.max(1, Math.min(600, remainingSeconds));
  try {
    const url = await getSignedUrl(getS3(), new GetObjectCommand({
      Bucket: BUCKET, Key: manifest.resultKey,
      ResponseContentDisposition: 'attachment; filename="signed.ipa"',
      ResponseContentType: 'application/octet-stream'
    }), {expiresIn});
    const expiresAtMs = Date.now() + expiresIn * 1000;
    res.set('Cache-Control', 'no-store').json({url, expiresIn, expiresAt: new Date(expiresAtMs).toISOString(), expiresAtMs});
  } catch (error) {
    console.error(JSON.stringify({event: 'tigris_download_presign_failed', requestId: req.requestId || null, jobId: manifest.id, message: safeTerminalLine(messageOf(error)).slice(0, 300), code: error?.Code || error?.code || null, status: error?.$metadata?.httpStatusCode || null}));
    res.status(503).json({error: 'Could not create the download link. Check object storage configuration and try again shortly.'});
  }
});

app.post('/api/jobs/:id/ota-url', actionLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  if (manifest.status !== 'completed') return res.status(409).json({error: 'Signed IPA is not ready for OTA installation.'});
  await expireSignedResultIfNeeded(manifest);
  if (!manifest.resultKey) return res.status(410).json({error: `This signed IPA expired and was deleted after ${SIGNED_IPA_RETENTION_MINUTES} minutes. Sign the app again for a new OTA link.`});
  const metadata = manifest.otaMetadata || {};
  if (!metadata.bundleId) return res.status(409).json({error: 'Could not determine the app Bundle ID. Add a Bundle ID in Advanced options and sign again to enable OTA installation.'});
  try {
    const installToken = crypto.randomBytes(32).toString('base64url');
    manifest.otaTokenHash = hashToken(installToken).toString('hex');
    const resultExpiresAt = Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS));
    manifest.otaExpiresAt = Math.min(Date.now() + 24 * 60 * 60 * 1000, resultExpiresAt);
    await putManifest(manifest);
    const baseOrigin = (PUBLIC_ORIGIN || 'https://xsigner.onrender.com').replace(/\/+$/, '');
    const manifestUrl = `${baseOrigin}/ota/${manifest.id}/${installToken}/manifest.plist`;
    const installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;
    res.set('Cache-Control', 'no-store').json({
      appName: metadata.appName || 'Signed app', bundleId: metadata.bundleId,
      version: metadata.version || '1.0', manifestUrl, installUrl,
      expiresAt: new Date(manifest.otaExpiresAt).toISOString(), expiresAtMs: manifest.otaExpiresAt
    });
  } catch (error) {
    console.error(JSON.stringify({event: 'tigris_ota_link_generation_failed', requestId: req.requestId || null, jobId: manifest.id, message: safeTerminalLine(messageOf(error)).slice(0, 300), code: error?.Code || error?.code || null, status: error?.$metadata?.httpStatusCode || null}));
    res.status(503).json({error: 'Could not create the OTA installation link.'});
  }
});

app.get('/ota/:id/:token/manifest.plist', async (req, res) => {
  const {id, token} = req.params;
  if (!validateId(id)) return res.status(404).type('text').send('Not found');
  try {
    const manifest = await maybeManifest(id);
    if (!manifest || manifest.status !== 'completed' || !manifest.resultKey || !manifest.otaTokenHash || !tokenMatches(token, manifest.otaTokenHash) || Date.now() > Number(manifest.otaExpiresAt || 0)) {
      return res.status(404).type('text').send('Installation link expired or unavailable');
    }
    await expireSignedResultIfNeeded(manifest);
    if (!manifest.resultKey) return res.status(404).type('text').send('Signed IPA expired and was deleted');
    const metadata = manifest.otaMetadata || {};
    if (!metadata.bundleId) return res.status(409).type('text').send('The signed app is missing its Bundle ID.');
    const remainingSeconds = Math.floor((Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS)) - Date.now()) / 1000);
    if (remainingSeconds < 1) return res.status(404).type('text').send('Signed IPA expired and was deleted');
    const ipaUrl = await getSignedUrl(getS3(), new GetObjectCommand({Bucket: BUCKET, Key: manifest.resultKey, ResponseContentType: 'application/octet-stream'}), {expiresIn: Math.max(1, Math.min(600, remainingSeconds))});
    const escapeXml = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&apos;');
    const title = escapeXml(metadata.appName || 'Signed app');
    const bundleId = escapeXml(metadata.bundleId);
    const version = escapeXml(metadata.version || '1.0');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${escapeXml(ipaUrl)}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${bundleId}</string><key>bundle-version</key><string>${version}</string><key>kind</key><string>software</string><key>title</key><string>${title}</string></dict></dict></array></dict></plist>`;
    res.set({'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}).send(xml);
  } catch (error) {
    console.error(JSON.stringify({event: 'tigris_ota_manifest_failed', requestId: req.requestId || null, jobId: id, message: safeTerminalLine(messageOf(error)).slice(0, 300), code: error?.Code || error?.code || null, status: error?.$metadata?.httpStatusCode || null}));
    res.status(503).type('text').send('Could not generate installation manifest');
  }
});

async function runCommand(command, args, {cwd, timeout = 60_000} = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {cwd, stdio: ['ignore', 'pipe', 'pipe'], env: {...process.env, NO_COLOR: '1', TERM: 'dumb'}});
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { if (stdout.length < 1_000_000) stdout += chunk.toString('utf8').slice(0, 1_000_000 - stdout.length); });
    child.stderr.on('data', chunk => { if (stderr.length < 1_000_000) stderr += chunk.toString('utf8').slice(0, 1_000_000 - stderr.length); });
    const timer = setTimeout(() => child.kill('SIGTERM'), timeout);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`${command} failed (${code}): ${(stderr || stdout).slice(-1000)}`));
      else resolve({stdout, stderr});
    });
  });
}
async function readIpaMetadata(ipaPath) {
  const listing = await execFileAsync('unzip', ['-Z1', ipaPath], {encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60_000});
  const candidates = String(listing.stdout).split(/\r?\n/).filter(name => /^Payload\/[^/]+\.app\/Info\.plist$/.test(name));
  const infoPath = candidates.sort((a, b) => a.length - b.length)[0];
  if (!infoPath) throw new Error('IPA does not contain a root app Info.plist.');
  const plistResult = await execFileAsync('unzip', ['-p', ipaPath, infoPath], {encoding: 'buffer', maxBuffer: 16 * 1024 * 1024, timeout: 60_000});
  const buffer = Buffer.isBuffer(plistResult.stdout) ? plistResult.stdout : Buffer.from(plistResult.stdout);
  return await new Promise((resolve, reject) => {
    const script = "import plistlib,json,sys; d=plistlib.loads(sys.stdin.buffer.read()); keys=['CFBundleIdentifier','CFBundleDisplayName','CFBundleName','CFBundleShortVersionString','CFBundleVersion']; print(json.dumps({k:d.get(k) for k in keys if isinstance(d.get(k),(str,int,float))}))";
    const child = spawn('python3', ['-c', script], {stdio: ['pipe', 'pipe', 'pipe']});
    let out = '', err = '';
    child.stdout.on('data', chunk => out += chunk.toString('utf8'));
    child.stderr.on('data', chunk => err += chunk.toString('utf8'));
    child.on('error', reject);
    child.on('close', code => {
      if (code !== 0) return reject(new Error(`Could not parse app Info.plist: ${err.slice(-500)}`));
      try { resolve(JSON.parse(out)); } catch (error) { reject(error); }
    });
    child.stdin.end(buffer);
  });
}
async function findFilesByExtension(root, extension) {
  const result = [];
  async function visit(dir) {
    for (const entry of await fsp.readdir(dir, {withFileTypes: true})) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await visit(full);
      else if (entry.isFile() && path.extname(entry.name).toLowerCase() === extension) result.push(full);
    }
  }
  await visit(root);
  return result;
}

async function writeS3ObjectToFile(key, destination, onBytes = () => {}) {
  const response = await getS3().send(new GetObjectCommand({Bucket: BUCKET, Key: key}));
  const counter = new Transform({
    transform(chunk, _encoding, callback) {
      try { onBytes(chunk.length); callback(null, chunk); }
      catch (error) { callback(error); }
    }
  });
  await pipeline(response.Body, counter, fs.createWriteStream(destination, {flags: 'wx'}));
}

const manifestFlushTimers = new Map();
const manifestFlushPromises = new Map();
const MAX_JOB_LOGS = 240;
function scheduleManifestFlush(manifest) {
  if (manifestFlushTimers.has(manifest.id)) return;
  const timer = setTimeout(() => {
    manifestFlushTimers.delete(manifest.id);
    const previous = manifestFlushPromises.get(manifest.id) || Promise.resolve();
    const pending = previous.catch(() => {}).then(() => putManifest(manifest)).catch(error => {
      console.warn('could not persist live job output:', messageOf(error));
    });
    manifestFlushPromises.set(manifest.id, pending);
  }, 2500);
  timer.unref?.();
  manifestFlushTimers.set(manifest.id, timer);
}
async function flushManifest(manifest) {
  const timer = manifestFlushTimers.get(manifest.id);
  if (timer) clearTimeout(timer);
  manifestFlushTimers.delete(manifest.id);
  const previous = manifestFlushPromises.get(manifest.id) || Promise.resolve();
  const pending = previous.catch(() => {}).then(() => putManifest(manifest));
  manifestFlushPromises.set(manifest.id, pending);
  await pending;
}
function appendJobLog(manifest, message, stream = 'system') {
  // Generated status messages are not filtered with a certificate password. Raw signer
  // output and error detail are scrubbed separately before this logger receives them.
  const clean = safeTerminalLine(message);
  if (!clean) return;
  manifest.logs ||= [];
  manifest.logSequence = Number(manifest.logSequence || 0) + 1;
  manifest.logs.push({id: manifest.logSequence, at: Date.now(), stream, message: clean});
  if (manifest.logs.length > MAX_JOB_LOGS) manifest.logs.splice(0, manifest.logs.length - MAX_JOB_LOGS);
  scheduleManifestFlush(manifest);
}
function updateProgressFromZsignLine(manifest, line) {
  const lower = line.toLowerCase();
  // zsign has no built-in percentage. The pinned source build emits this
  // operation counter after each completed Mach-O or bundle-signing task.
  const operationProgress = line.match(/>>>\s*Progress:\s*(\d+)\s*\/\s*(\d+)/i);
  if (operationProgress) {
    const done = Number(operationProgress[1]);
    const total = Number(operationProgress[2]);
    if (Number.isFinite(done) && Number.isFinite(total) && total > 0) {
      const signingProgress = 72 + Math.floor(14 * Math.min(total, done) / total);
      manifest.progress = Math.max(Number(manifest.progress || 0), Math.min(86, signingProgress));
    }
  }
  if (lower.includes('unzip ok')) manifest.progress = Math.max(Number(manifest.progress || 0), 72);
  if (lower.includes('>>> signed ok!')) manifest.progress = Math.max(Number(manifest.progress || 0), 86);
  if (lower.includes('>>> archiving:')) manifest.progress = Math.max(Number(manifest.progress || 0), 88);
  if (lower.includes('>>> archive ok!')) manifest.progress = Math.max(Number(manifest.progress || 0), 90);
  if (lower.includes('>>> done.')) manifest.progress = Math.max(Number(manifest.progress || 0), 91);
}
function spawnSigner(args, cwd, passwordForRedaction, onLine) {
  return new Promise((resolve, reject) => {
    const child = spawn(SIGNER, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {...process.env, NO_COLOR: '1', TERM: 'dumb'}
    });
    let out = '', err = '', outBytes = 0, errBytes = 0;
    let outPending = '', errPending = '';
    const maxCapture = 1024 * 1024;
    const capture = (which, chunk) => {
      const text = chunk.toString('utf8');
      if (which === 'stdout') {
        if (outBytes < maxCapture) { out += text.slice(0, Math.max(0, maxCapture - outBytes)); outBytes += chunk.length; }
        outPending += text;
        const lines = outPending.split(/[\r\n]+/);
        outPending = lines.pop() || '';
        for (const line of lines) onLine(line, 'stdout');
      } else {
        if (errBytes < maxCapture) { err += text.slice(0, Math.max(0, maxCapture - errBytes)); errBytes += chunk.length; }
        errPending += text;
        const lines = errPending.split(/[\r\n]+/);
        errPending = lines.pop() || '';
        for (const line of lines) onLine(line, 'stderr');
      }
    };
    child.stdout.on('data', chunk => capture('stdout', chunk));
    child.stderr.on('data', chunk => capture('stderr', chunk));
    child.stdout.on('end', () => { if (outPending) { onLine(outPending, 'stdout'); outPending = ''; } });
    child.stderr.on('end', () => { if (errPending) { onLine(errPending, 'stderr'); errPending = ''; } });
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      onLine('zsign exceeded the configured signing timeout; stopping the process.', 'stderr');
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 10_000).unref();
    }, Number(process.env.SIGN_TIMEOUT_MS || 45 * 60 * 1000));
    child.on('error', error => { clearTimeout(timeout); reject(error); });
    child.on('close', code => {
      clearTimeout(timeout);
      const scrub = text => removeSecretValue(text, passwordForRedaction);
      resolve({code, timedOut, out: scrub(out), err: scrub(err)});
    });
  });
}

const pendingQueue = [];
const queuedIds = new Set();
const activeIds = new Set();
let pumping = false;
async function enqueue(id) {
  if (SHARED_QUEUE_ENABLED) {
    if (!signingQueue) throw new Error('This instance is configured as a signing worker and cannot enqueue API requests.');
    await signingQueue.add('sign', {id}, {jobId: id, attempts: 1, removeOnComplete: true, removeOnFail: 1000});
    return;
  }
  if (!queuedIds.has(id) && !activeIds.has(id)) { pendingQueue.push(id); queuedIds.add(id); }
  void pumpQueue();
}
async function pumpQueue() {
  if (pumping) return;
  pumping = true;
  try {
    while (pendingQueue.length && activeIds.size < MAX_CONCURRENT_JOBS) {
      const id = pendingQueue.shift(); queuedIds.delete(id); activeIds.add(id);
      void runSigningJob(id).catch(error => console.error('worker error:', messageOf(error))).finally(() => {
        activeIds.delete(id);
        void pumpQueue();
      });
    }
  } finally { pumping = false; }
}

async function runSigningJob(id) {
  let manifest;
  let password = '';
  const workDir = path.join(WORK_ROOT, id);
  try {
    manifest = await getManifest(id);
    if (manifest.status !== 'queued' && manifest.status !== 'signing') return;
    if (!fs.existsSync(SIGNER)) throw new Error('The zsign binary is missing from this container. Check the Docker build and ZSIGN_BIN setting.');
    password = manifest.passwordCipher ? decryptPassword(manifest.passwordCipher) : '';
    const startedAt = Date.now();
    manifest.queuedAt = Number(manifest.queuedAt || manifest.createdAt || startedAt);
    manifest.startedAt = startedAt;
    manifest.attemptCount = Number(manifest.attemptCount || 0) + 1;
    manifest.status = 'signing'; manifest.phase = 'downloading'; manifest.progress = Math.max(64, Number(manifest.progress || 0)); manifest.error = null;
    console.log(JSON.stringify({event: 'signing_job_started', requestId: manifest.requestId || null, jobId: id, attempt: manifest.attemptCount, queueWaitMs: Math.max(0, startedAt - manifest.queuedAt), phase: manifest.phase}));
    manifest.logs ||= []; manifest.logSequence = Number(manifest.logSequence || 0);
    appendJobLog(manifest, 'Worker started. Preparing local signing workspace.', 'system');
    await flushManifest(manifest);
    await fsp.rm(workDir, {recursive: true, force: true});
    await fsp.mkdir(workDir, {recursive: true});
    const local = {};
    const totalInputBytes = Object.values(manifest.uploads || {}).reduce((sum, upload) => sum + Number(upload.expectedSize || 0), 0);
    let downloadedInputBytes = 0;
    for (const kind of Object.keys(manifest.uploads || {})) {
      const upload = manifest.uploads[kind];
      local[kind] = path.join(workDir, `input-${kind}${path.extname(upload.filename).toLowerCase()}`);
      if (upload.sourceUrl) {
        appendJobLog(manifest, `Downloading ${kind} from the supplied HTTPS URL (${upload.filename}) into temporary signing workspace.`, 'system');
        let lastLoggedPercent = -10;
        const remoteIndex = Object.keys(manifest.uploads).indexOf(kind);
        const remoteCount = Math.max(1, Object.values(manifest.uploads).filter(value => value.sourceUrl).length);
        const downloadedSize = await downloadRemoteToFile(upload.sourceUrl, local[kind], Number(upload.maxBytes || (kind === 'ipa' ? MAX_IPA_BYTES : MAX_SMALL_FILE_BYTES)), (loaded, total) => {
          if (total && total > 0) {
            const pct = Math.floor(100 * loaded / total);
            manifest.progress = Math.max(Number(manifest.progress || 0), Math.min(70, 64 + Math.floor(6 * (remoteIndex + loaded / total) / remoteCount)));
            if (pct >= lastLoggedPercent + 10 || pct === 100) { lastLoggedPercent = Math.floor(pct / 10) * 10; appendJobLog(manifest, `${kind.toUpperCase()} URL download: ${pct}% (${formatBytesSafe(loaded)} / ${formatBytesSafe(total)}).`, 'system'); }
          } else if (loaded > 0 && loaded % (10 * 1024 * 1024) < 1024 * 1024) {
            appendJobLog(manifest, `${kind.toUpperCase()} URL download: ${formatBytesSafe(loaded)} received (server did not provide total size).`, 'system');
          }
          scheduleManifestFlush(manifest);
        });
        upload.expectedSize = downloadedSize;
        upload.actualSize = downloadedSize;
      } else {
        appendJobLog(manifest, `Downloading ${kind} (${upload.expectedSize} bytes) from private Tigris storage.`, 'system');
        let lastMilestone = -10;
        let downloadedForThisFile = 0;
        await writeS3ObjectToFile(upload.key, local[kind], bytes => {
          downloadedInputBytes += bytes;
          downloadedForThisFile += bytes;
          if (totalInputBytes > 0) manifest.progress = Math.max(Number(manifest.progress || 0), Math.min(70, 64 + Math.floor(6 * downloadedInputBytes / totalInputBytes)));
          const pct = upload.expectedSize ? Math.floor(100 * downloadedForThisFile / upload.expectedSize) : 0;
          if (pct >= lastMilestone + 10 || pct === 100) { lastMilestone = Math.floor(pct / 10) * 10; appendJobLog(manifest, `${kind.toUpperCase()} Tigris download: ${pct}% (${formatBytesSafe(downloadedForThisFile)} / ${formatBytesSafe(upload.expectedSize)}).`, 'system'); }
          scheduleManifestFlush(manifest);
        });
      }
      const info = await fsp.stat(local[kind]);
      if (upload.expectedSize && info.size !== upload.expectedSize) throw new Error(`Downloaded ${kind} size verification failed.`);
      appendJobLog(manifest, `Verified ${kind} on the signing worker (${info.size} bytes).`, 'system');
      await flushManifest(manifest);
    }
    const inputMetadata = await readIpaMetadata(local.ipa).catch(error => {
      appendJobLog(manifest, `Could not read IPA metadata automatically: ${messageOf(error)}`, 'stderr');
      return {};
    });
    const finalMetadata = {
      bundleId: manifest.settings?.bundleId || inputMetadata.CFBundleIdentifier || '',
      appName: manifest.settings?.bundleName || inputMetadata.CFBundleDisplayName || inputMetadata.CFBundleName || path.basename(manifest.uploads.ipa.filename, path.extname(manifest.uploads.ipa.filename)),
      version: manifest.settings?.bundleVersion || inputMetadata.CFBundleShortVersionString || inputMetadata.CFBundleVersion || '1.0'
    };
    manifest.otaMetadata = finalMetadata;
    await flushManifest(manifest);

    const dylibsToInject = [];
    if (local.dylib) dylibsToInject.push(local.dylib);
    if (local.deb) {
      const extractedDeb = path.join(workDir, 'deb-extracted');
      await fsp.mkdir(extractedDeb, {recursive: true});
      appendJobLog(manifest, 'Extracting the uploaded .deb package to find injectable .dylib files.', 'system');
      await runCommand('dpkg-deb', ['-x', local.deb, extractedDeb], {cwd: workDir, timeout: 120_000});
      const foundDylibs = await findFilesByExtension(extractedDeb, '.dylib');
      if (foundDylibs.length === 0) throw new Error('The uploaded .deb contains no .dylib files to inject. Upload a tweak package that contains a compatible dylib.');
      if (foundDylibs.length > 8) throw new Error('The uploaded .deb contains more than 8 dylib files. Please use a smaller package or upload a specific .dylib.');
      dylibsToInject.push(...foundDylibs);
      appendJobLog(manifest, `Found ${foundDylibs.length} dylib file(s) in the .deb package.`, 'system');
    }
    manifest.phase = 'signing'; manifest.progress = 70;
    appendJobLog(manifest, 'Starting upstream zsign CLI (version 1.1.2 build target).', 'system');
    await flushManifest(manifest);
    const output = path.join(workDir, 'signed.ipa');
    const args = ['-k', local.certificate];
    if (password.length > 0) args.push('-p', password);
    args.push('-m', local.profile, '-o', output, '-z', '9', '-t', workDir, local.ipa);
    if (manifest.settings?.bundleId) args.push('-b', manifest.settings.bundleId);
    if (manifest.settings?.bundleName) args.push('-n', manifest.settings.bundleName);
    if (manifest.settings?.bundleVersion) args.push('-r', manifest.settings.bundleVersion);
    if (local.icon) args.push('-I', local.icon);
    if (manifest.settings?.injectExtensions && dylibsToInject.length) args.push('-P');
    for (const dylibPath of dylibsToInject) args.push('-l', dylibPath);
    let archiveHeartbeat = null;
    let archivingActive = false;
    const stopArchiveHeartbeat = () => {
      if (archiveHeartbeat) clearInterval(archiveHeartbeat);
      archiveHeartbeat = null;
      archivingActive = false;
    };
    let result;
    manifest.zsignStartedAt = Date.now();
    try {
      result = await spawnSigner(args, workDir, password, (line, stream) => {
        const clean = safeTerminalLine(line, password);
        if (!clean) return;
        const lower = clean.toLowerCase();
        if (lower.includes('>>> archiving:') && !archivingActive) {
          archivingActive = true;
          manifest.phase = 'archiving';
          manifest.progress = Math.max(Number(manifest.progress || 0), 88);
          appendJobLog(manifest, 'Archiving the signed IPA: writing the final package. Large apps may take a while; zsign is still working.', 'system');
          archiveHeartbeat = setInterval(() => {
            if (manifest.phase !== 'archiving') return stopArchiveHeartbeat();
            appendJobLog(manifest, 'Still archiving the IPA. The final archive is being written; this step can take several minutes for large apps.', 'system');
            manifest.progress = Math.min(90, Math.max(88, Number(manifest.progress || 0) + 1));
            scheduleManifestFlush(manifest);
          }, 10_000);
          archiveHeartbeat.unref?.();
        }
        appendJobLog(manifest, clean, stream);
        updateProgressFromZsignLine(manifest, clean);
        if (lower.includes('>>> archive ok!') || lower.includes('>>> done.')) {
          stopArchiveHeartbeat();
          if (manifest.phase === 'archiving') manifest.phase = 'signing';
        }
        scheduleManifestFlush(manifest);
      });
      manifest.zsignFinishedAt = Date.now();
    } finally {
      stopArchiveHeartbeat();
    }
    await flushManifest(manifest);
    if (result.timedOut) {
      manifest.failureCode = 'SIGNING_TIMEOUT';
      throw new Error('Signing exceeded the configured time limit. Try a smaller IPA or increase SIGN_TIMEOUT_MS.');
    }
    const outputStat = await fsp.stat(output).catch(() => null);
    if (result.code !== 0 || !outputStat?.isFile() || outputStat.size < 1) {
      const detail = (result.err || result.out || 'zsign reported a failure').slice(-2500);
      throw new Error(removeSecretValue(detail, password));
    }
    manifest.phase = 'uploading_result'; manifest.progress = Math.max(91, Number(manifest.progress || 0));
    manifest.resultKey = `signed/${id}/signed.ipa`;
    appendJobLog(manifest, `zsign exited successfully. Signed IPA size: ${outputStat.size} bytes. Uploading result to private storage.`, 'system');
    await flushManifest(manifest);
    const uploader = new Upload({
      client: getS3(),
      params: {
        Bucket: BUCKET, Key: manifest.resultKey,
        Body: fs.createReadStream(output), ContentLength: outputStat.size,
        ContentType: 'application/octet-stream',
        ContentDisposition: 'attachment; filename="signed.ipa"',
        Metadata: {jobid: id, purpose: 'signed-ipa'}
      },
      queueSize: 2, partSize: Math.max(64 * 1024 * 1024, PART_SIZE), leavePartsOnError: false
    });
    let lastResultUploadMark = -5;
    uploader.on('httpUploadProgress', event => {
      const loaded = Number(event.loaded || 0);
      const total = Number(event.total || outputStat.size);
      if (total > 0) {
        manifest.progress = Math.max(Number(manifest.progress || 0), Math.min(99, 91 + Math.floor(8 * loaded / total)));
        const pct = Math.min(100, Math.floor(100 * loaded / total));
        if (pct >= lastResultUploadMark + 5 || pct === 100) {
          lastResultUploadMark = Math.floor(pct / 5) * 5;
          appendJobLog(manifest, `Tigris result upload: ${pct}% (${formatBytesSafe(loaded)} / ${formatBytesSafe(total)}).`, 'system');
        }
      }
      scheduleManifestFlush(manifest);
    });
    await uploader.done();
    await flushManifest(manifest);
    manifest.resultSize = outputStat.size;
    manifest.completedAt = Date.now();
    manifest.resultExpiresAt = manifest.completedAt + SIGNED_IPA_RETENTION_MS;
    console.log(JSON.stringify({
      event: 'signing_job_completed', requestId: manifest.requestId || null, jobId: id,
      attempt: Number(manifest.attemptCount || 1),
      queueWaitMs: Math.max(0, Number(manifest.startedAt || manifest.completedAt) - Number(manifest.queuedAt || manifest.createdAt || manifest.completedAt)),
      signingDurationMs: manifest.zsignStartedAt && manifest.zsignFinishedAt ? Math.max(0, manifest.zsignFinishedAt - manifest.zsignStartedAt) : null,
      workerDurationMs: Math.max(0, manifest.completedAt - Number(manifest.startedAt || manifest.completedAt)),
      totalDurationMs: Math.max(0, manifest.completedAt - Number(manifest.createdAt || manifest.completedAt)),
      resultSizeBytes: outputStat.size, retentionMinutes: SIGNED_IPA_RETENTION_MINUTES
    }));
    await cleanupInputs(manifest, false);
    manifest.passwordCipher = null;
    manifest.status = 'completed'; manifest.phase = 'completed'; manifest.progress = 100;
    manifest.error = null;
    appendJobLog(manifest, 'Result uploaded. Temporary source files and certificate material will now be removed.', 'system');
    password = '';
    await flushManifest(manifest);
    if (SHARED_QUEUE_ENABLED && signingQueue) {
      try {
        await signingQueue.add('expire-result', {id}, {
          jobId: `expire-${id}`, delay: SIGNED_IPA_RETENTION_MS,
          attempts: 5, backoff: {type: 'exponential', delay: 5_000}, removeOnComplete: true, removeOnFail: 1000
        });
      } catch (error) {
        console.warn(JSON.stringify({event: 'result_expiry_schedule_failed', jobId: id, message: safeTerminalLine(messageOf(error)).slice(0, 250)}));
      }
    }
  } catch (error) {
    const rawError = messageOf(error);
    const safeError = safeTerminalLine(rawError, password).slice(0, 2000) || 'Signing job failed.';
    const failedAt = Date.now();
    console.error(JSON.stringify({
      event: 'signing_job_failed', requestId: manifest?.requestId || null, jobId: id,
      attempt: Number(manifest?.attemptCount || 1), phase: manifest?.phase || 'unknown',
      code: manifest?.failureCode || (error?.code && /^[A-Z][A-Z0-9_]{1,63}$/.test(error.code) ? error.code : 'SIGNING_FAILED'),
      queueWaitMs: manifest?.startedAt ? Math.max(0, Number(manifest.startedAt) - Number(manifest.queuedAt || manifest.createdAt || manifest.startedAt)) : null,
      attemptDurationMs: manifest?.startedAt ? Math.max(0, failedAt - Number(manifest.startedAt)) : null,
      signingDurationMs: manifest?.zsignStartedAt ? Math.max(0, Number(manifest.zsignFinishedAt || failedAt) - Number(manifest.zsignStartedAt)) : null,
      message: safeError.slice(0, 500)
    }));
    if (manifest) {
      appendJobLog(manifest, safeError, 'error');
      manifest.status = 'failed'; manifest.phase = 'failed'; manifest.error = safeError;
      manifest.passwordCipher = null;
      await cleanupInputs(manifest, true).catch(() => {});
      if (manifest.resultKey) await removeObject(manifest.resultKey);
      await flushManifest(manifest).catch(() => {});
    }
  } finally {
    password = '';
    const pendingFlushTimer = manifestFlushTimers.get(id);
    if (pendingFlushTimer) clearTimeout(pendingFlushTimer);
    manifestFlushTimers.delete(id);
    manifestFlushPromises.delete(id);
    await fsp.rm(workDir, {recursive: true, force: true}).catch(() => {});
  }
}

async function recoverJobs({recoverInterruptedImmediately = false} = {}) {
  if (SHARED_QUEUE_ENABLED || !storageConfigured() || !JOB_ENCRYPTION_KEY) return;
  try {
    const keys = await listManifestKeys();
    const now = Date.now();
    for (const key of keys) {
      const id = key.split('/')[1];
      if (!validateId(id) || activeIds.has(id) || queuedIds.has(id)) continue;
      const manifest = await maybeManifest(id);
      if (!manifest) continue;
      if (manifest.status === 'queued') await enqueue(id);
      else if (manifest.status === 'signing' && (recoverInterruptedImmediately || now - Number(manifest.updatedAt || 0) > STALE_JOB_MS)) {
        manifest.status = 'queued'; manifest.phase = 'queued';
        manifest.progress = 64; manifest.error = null;
        await putManifest(manifest);
        await enqueue(id);
      }
    }
  } catch (error) {
    console.warn('queue recovery unavailable:', messageOf(error));
  }
}
async function cleanupExpiredSignedResults() {
  if (!storageConfigured()) return;
  try {
    const keys = await listManifestKeys();
    for (const key of keys) {
      const id = key.split('/')[1];
      if (!validateId(id)) continue;
      const manifest = await maybeManifest(id);
      if (!manifest || manifest.status !== 'completed' || !manifest.resultKey) continue;
      await expireSignedResultIfNeeded(manifest);
    }
  } catch (error) {
    console.warn('signed IPA retention sweep failed:', messageOf(error));
  }
}

async function cleanupExpiredJobs() {
  if (!storageConfigured()) return;
  try {
    for (const key of await listManifestKeys()) {
      const id = key.split('/')[1];
      if (!validateId(id) || activeIds.has(id) || queuedIds.has(id)) continue;
      const manifest = await maybeManifest(id);
      if (!manifest) continue;
      const age = Date.now() - Number(manifest.createdAt || manifest.updatedAt || Date.now());
      const ttl = manifest.status === 'completed' || manifest.status === 'failed' ? JOB_TTL_MS : UPLOAD_TTL_MS;
      if (age > ttl) {
        await cleanupInputs(manifest, true).catch(() => {});
        if (manifest.resultKey) await removeObject(manifest.resultKey);
        if (!isLocalManifestStorage()) await removeObject(key);
        await fsp.rm(localManifestPath(id), {force: true}).catch(() => {});
        manifestCache.delete(id);
      }
    }
  } catch (error) {
    console.warn('expired job cleanup unavailable:', messageOf(error));
  }
}

// The API remains public, while the reference material stays owner-IP-only.
const docsRoot = path.join(process.cwd(), 'docs');
app.get(['/doc', '/doc/'], requireOwnerDocs, (_req, res) => res.sendFile(path.join(docsRoot, 'index.html')));
app.get('/doc/openapi.json', requireOwnerDocs, (_req, res) => res.type('application/json').sendFile(path.join(docsRoot, 'openapi.json')));

// API-only: do not serve website tools, certificate browsing, or browser-only routes.
app.use((req, res) => res.status(404).set('Cache-Control', 'no-store').json({
  success: false, ok: false, error: 'API endpoint not found.',
  signEndpoint: 'POST /sign', discordEndpoint: 'POST /api/v1/discord/sign'
}));

app.use((error, req, res, _next) => {
  console.error(JSON.stringify({event: 'request_failed', requestId: req?.requestId || null, message: safeTerminalLine(messageOf(error)).slice(0, 500)}));
  if (res.headersSent) return;
  if (error?.code === 'LIMIT_FILE_SIZE' || error?.code === 'LIMIT_FILE_COUNT') return res.status(413).json({error: 'Uploaded files exceed the configured upload limit.', code: 'PAYLOAD_TOO_LARGE'});
  if (error?.name === 'MulterError') return res.status(400).json({error: 'Invalid multipart file upload.', code: 'INVALID_MULTIPART'});
  const status = Number(error?.status);
  if (Number.isInteger(status) && status >= 400 && status < 600) return res.status(status).json({error: messageOf(error), code: error.code && /^[A-Z][A-Z0-9_]{1,63}$/.test(error.code) ? error.code : undefined});
  res.status(500).json({error: 'Unexpected server error.', code: 'INTERNAL_ERROR'});
});

let server = null;
let sharedSigningWorker = null;
if (SHARED_QUEUE_ENABLED && process.env.RUN_SIGNING_WORKER !== 'false') {
  sharedSigningWorker = new Worker(QUEUE_NAME, async job => {
    const id = String(job.data?.id || '');
    if (!validateId(id)) throw new Error('Queue job has an invalid signing job ID.');
    if (job.name === 'expire-result') {
      const manifest = await maybeManifest(id);
      if (manifest) await expireSignedResultIfNeeded(manifest);
      return {expired: true};
    }
    if (job.name !== 'sign') throw new Error('Queue job type is not supported.');
    await runSigningJob(id);
    return {processed: true};
  }, {connection: redisConnectionOptions({worker: true}), concurrency: MAX_CONCURRENT_JOBS, lockDuration: 60_000, stalledInterval: 30_000, maxStalledCount: 2});
  sharedSigningWorker.on('completed', job => console.log(JSON.stringify({event: job?.name === 'expire-result' ? 'signed_result_expiry_task_completed' : 'signing_job_queue_task_completed', jobId: job?.data?.id || null})));
  sharedSigningWorker.on('failed', (job, error) => console.error(JSON.stringify({event: 'signing_job_queue_failed', jobId: job?.id || null, message: safeTerminalLine(messageOf(error)).slice(0, 300)})));
  sharedSigningWorker.on('error', error => console.error(JSON.stringify({event: 'signing_queue_worker_error', message: safeTerminalLine(messageOf(error)).slice(0, 300)})));
}
if (!WORKER_ONLY) {
  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(JSON.stringify({event: 'service_started', port: PORT, queue: SHARED_QUEUE_ENABLED ? 'bullmq' : 'in-process', worker: Boolean(sharedSigningWorker), storageConfigured: storageConfigured()}));
    // With BullMQ the queue itself persists jobs and recovers stalled workers; local recovery is standalone-only.
    if (!SHARED_QUEUE_ENABLED) void recoverJobs({recoverInterruptedImmediately: true});
  });
}
if (WORKER_ONLY && !sharedSigningWorker) throw new Error('Worker-only mode requires REDIS_URL and RUN_SIGNING_WORKER=true.');
if (WORKER_ONLY) console.log(JSON.stringify({event: 'worker_started', queue: QUEUE_NAME, concurrency: MAX_CONCURRENT_JOBS}));
const maintenanceIntervalMs = WORKER_ONLY ? 0 : Number(process.env.S3_MAINTENANCE_INTERVAL_MS || 0);
const maintenanceTimer = maintenanceIntervalMs >= 60 * 60_000 ? setInterval(() => { void recoverJobs(); void cleanupExpiredJobs(); if (SHARED_QUEUE_ENABLED) void cleanupExpiredSignedResults(); }, maintenanceIntervalMs).unref() : null;
const signedResultCleanupTimer = (WORKER_ONLY || SHARED_QUEUE_ENABLED) ? null : setInterval(() => { void cleanupExpiredSignedResults(); }, SIGNED_IPA_CLEANUP_INTERVAL_MS).unref();
if (!WORKER_ONLY) void cleanupExpiredSignedResults();

async function shutdown() {
  if (maintenanceTimer) clearInterval(maintenanceTimer);
  if (signedResultCleanupTimer) clearInterval(signedResultCleanupTimer);
  if (sharedSigningWorker) await sharedSigningWorker.close().catch(() => {});
  if (signingQueue) await signingQueue.close().catch(() => {});
  if (apiQuotaRedis) await apiQuotaRedis.quit().catch(() => {});
  if (server) server.close(() => process.exit(0));
  else process.exit(0);
  setTimeout(() => process.exit(1), 25_000).unref();
}
process.on('SIGTERM', () => { void shutdown(); });
process.on('SIGINT', () => { void shutdown(); });
