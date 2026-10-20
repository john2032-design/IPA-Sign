import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import dns from 'node:dns/promises';
import net from 'node:net';
import {spawn, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import multer from 'multer';
import {pipeline} from 'node:stream/promises';
import {Transform, Readable} from 'node:stream';
import {
  S3Client, CreateMultipartUploadCommand, UploadPartCommand,
  CompleteMultipartUploadCommand, AbortMultipartUploadCommand,
  PutObjectCommand, GetObjectCommand,
  DeleteObjectCommand, ListObjectsV2Command
} from '@aws-sdk/client-s3';
import {getSignedUrl} from '@aws-sdk/s3-request-presigner';
import {Upload} from '@aws-sdk/lib-storage';

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
const SIGNED_IPA_RETENTION_MINUTES = Number.isFinite(Number(process.env.SIGNED_IPA_TTL_MINUTES)) && Number(process.env.SIGNED_IPA_TTL_MINUTES) > 0 ? Number(process.env.SIGNED_IPA_TTL_MINUTES) : 10;
const SIGNED_IPA_RETENTION_MS = Math.max(60_000, SIGNED_IPA_RETENTION_MINUTES * 60 * 1000);
const SIGNED_IPA_CLEANUP_INTERVAL_MS = Math.max(10_000, Number(process.env.SIGNED_IPA_CLEANUP_INTERVAL_MS) || 10_000);
const MAX_CONCURRENT_JOBS = Math.max(1, Number(process.env.MAX_CONCURRENT_JOBS || 1));
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || '';
const JOB_ENCRYPTION_KEY = process.env.JOB_ENCRYPTION_KEY || '';
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || '';
const CERT_API_BASE = 'https://sideloading.net/api/certificates';
const execFileAsync = promisify(execFile);
const checkerUpload = multer({storage: multer.memoryStorage(), limits: {fileSize: 32 * 1024 * 1024, files: 2, fields: 3}}).fields([{name: 'p12', maxCount: 1}, {name: 'mobileprovision', maxCount: 1}]);
const API_SIGN_FILE_LIMITS = {
  ipa: MAX_IPA_BYTES,
  p12: MAX_SMALL_FILE_BYTES,
  mobileprovision: MAX_SMALL_FILE_BYTES,
  icon: MAX_SMALL_FILE_BYTES,
  deb: 256 * 1024 * 1024,
  dylib: 128 * 1024 * 1024
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
  limits: {fileSize: MAX_IPA_BYTES, files: 6, fields: 12, parts: 18, fieldNameSize: 64, fieldSize: 4096},
  fileFilter(_req, file, callback) {
    const ext = path.extname(file.originalname || '').toLowerCase();
    const allowed = {
      ipa: ['.ipa'], p12: ['.p12', '.pfx'], mobileprovision: ['.mobileprovision'],
      icon: ['.png'], deb: ['.deb'], dylib: ['.dylib']
    };
    if (!allowed[file.fieldname] || !allowed[file.fieldname].includes(ext)) {
      return callback(Object.assign(new Error(`Invalid file type for ${file.fieldname}.`), {status: 400}));
    }
    callback(null, true);
  }
}).fields([
  {name: 'ipa', maxCount: 1}, {name: 'p12', maxCount: 1}, {name: 'mobileprovision', maxCount: 1},
  {name: 'icon', maxCount: 1}, {name: 'deb', maxCount: 1}, {name: 'dylib', maxCount: 1}
]);

await fsp.mkdir(WORK_ROOT, {recursive: true});
await fsp.mkdir(MANIFEST_ROOT, {recursive: true, mode: 0o700});

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy: false, crossOriginEmbedderPolicy: false}));
app.use(express.json({limit: '1mb'}));
app.use(express.static(path.join(process.cwd(), 'public'), {maxAge: '1h', etag: true}));

const createLimiter = rateLimit({windowMs: 60_000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many jobs created. Try again in a minute.'}});
const partLimiter = rateLimit({windowMs: 60_000, limit: 240, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many upload requests. Slow down and retry.'}});
const actionLimiter = rateLimit({windowMs: 60_000, limit: 15, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many requests. Try again shortly.'}});
const pollLimiter = rateLimit({windowMs: 60_000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many status requests. Slow down briefly.'}});

let s3Client;
// Hot manifest cache: polling must not download manifest.json from object storage on every browser poll.
// S3-compatible storage is durable; cached metadata is only process memory.
const manifestCache = new Map();
const OWNER_IP = process.env.XSIGNER_OWNER_IP || '168.91.23.165';
function normalizedClientIp(req) { return String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/i, '').split('%')[0]; }
function isOwnerRequest(req) { return normalizedClientIp(req) === OWNER_IP; }
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
  // Fallback for jobs configured to store manifests in the S3-compatible bucket.
  if (isLocalManifestStorage()) throw Object.assign(new Error('Job not found in local metadata store.'), {code: 'ENOENT'});
  const response = await getS3().send(new GetObjectCommand({Bucket: BUCKET, Key: s3KeyForManifest(id)}));
  const body = await response.Body.transformToString();
  const manifest = JSON.parse(body);
  await persistManifestLocally(manifest);
  manifestCache.set(id, manifest);
  return manifest;
}
async function maybeManifest(id) {
  const cached = manifestCache.get(id);
  if (cached) return cached;
  try { return await getManifest(id); }
  catch (error) {
    if (error?.code === 'ENOENT' || error?.$metadata?.httpStatusCode === 404 || error?.name === 'NoSuchKey' || error?.name === 'NotFound') return null;
    throw error;
  }
}
async function authorizedJob(req, res, id) {
  if (!validateId(id)) { res.status(400).json({error: 'Invalid job ID.'}); return null; }
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try {
    const manifest = await maybeManifest(id);
    if (!manifest || !tokenMatches(token, manifest.tokenHash)) {
      res.status(404).json({error: 'Job not found or access token invalid.'});
      return null;
    }
    // On-demand recovery avoids a full object-storage scan at startup. This is especially
    // useful on one-instance Render services where in-memory queue state resets.
    if (!activeIds.has(id) && !queuedIds.has(id)) {
      if (manifest.status === 'queued') enqueue(id);
      else if (manifest.status === 'signing' && Date.now() - Number(manifest.updatedAt || 0) > STALE_JOB_MS) {
        manifest.status = 'queued'; manifest.phase = 'queued'; manifest.progress = 64; manifest.error = null;
        appendJobLog(manifest, 'Recovered an interrupted signing job after its worker stopped.', 'system');
        await flushManifest(manifest);
        enqueue(id);
      }
    }
    return manifest;
  } catch (error) {
    console.error('manifest read failed:', JSON.stringify({message: messageOf(error), code: error?.Code || error?.code || null, status: error?.$metadata?.httpStatusCode || null}));
    res.status(503).json({error: storageErrorForUser(error)});
    return null;
  }
}
async function signPartUrl(upload, partNumber) {
  return getSignedUrl(getS3(), new UploadPartCommand({
    Bucket: BUCKET, Key: upload.key, UploadId: upload.uploadId, PartNumber: partNumber,
    ContentLength: Math.min(PART_SIZE, upload.expectedSize - ((partNumber - 1) * PART_SIZE))
  }), {expiresIn: 3600});
}
async function listManifestKeys() {
  // Local manifests are authoritative in local mode; do not list or download remote manifest history.
  const entries = await fsp.readdir(MANIFEST_ROOT, {withFileTypes: true});
  const localKeys = entries.filter(entry => entry.isFile() && /^[0-9a-f-]{36}\.json$/i.test(entry.name))
    .map(entry => `jobs/${entry.name.slice(0, -5)}/manifest.json`);
  if (isLocalManifestStorage() || process.env.S3_RECOVER_ON_START !== 'true') return localKeys;
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
  catch (error) { console.warn('object cleanup failed:', messageOf(error)); }
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
    console.warn('signed IPA expiry deletion failed:', messageOf(error));
    return false;
  }
  manifest.resultKey = null;
  manifest.resultDeletedAt = Date.now();
  manifest.resultExpiresAt = expiresAt;
  appendJobLog(manifest, 'The signed IPA was automatically deleted from Tigris after 10 minutes.', 'system');
  await flushManifest(manifest).catch(error => console.warn('could not persist signed IPA expiry:', messageOf(error)));
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

async function verifyGoogleCaptcha(captchaToken, req) {
  if (!RECAPTCHA_SECRET_KEY) throw Object.assign(new Error('reCAPTCHA verification is not configured on the server. Add RECAPTCHA_SECRET_KEY in Render.'), {status: 503});
  const verifyBody = new URLSearchParams({secret: RECAPTCHA_SECRET_KEY, response: captchaToken});
  if (req.ip) verifyBody.set('remoteip', req.ip);
  const captchaResponse = await fetch('https://www.google.com/recaptcha/api/siteverify', {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'}, body: verifyBody, signal: AbortSignal.timeout(10_000)});
  const captcha = await captchaResponse.json();
  const expectedHosts = (process.env.RECAPTCHA_ALLOWED_HOSTNAMES || req.hostname || 'xsigner.onrender.com').split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
  if (!captchaResponse.ok || captcha.success !== true || !expectedHosts.includes(String(captcha.hostname || '').toLowerCase())) {
    console.warn('reCAPTCHA rejected a signing request:', JSON.stringify({success: captcha.success === true, hostname: captcha.hostname || null, errors: captcha['error-codes'] || []}));
    throw Object.assign(new Error('reCAPTCHA verification failed or expired. Complete the checkbox again and retry.'), {status: 403});
  }
}
function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a,b,c] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0 && c === 113);
  }
  if (family === 6) {
    const ip = address.toLowerCase();
    return ip === '::' || ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || /^fe[89ab]/.test(ip) || ip.startsWith('::ffff:');
  }
  return true;
}
async function validatePublicHttpsUrl(raw) {
  let url;
  try { url = new URL(String(raw || '').trim()); } catch { throw new Error('URL is invalid.'); }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname || (url.port && url.port !== '443')) throw new Error('URL must be a public HTTPS URL without embedded credentials or a non-standard port.');
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('Private or local URLs are not allowed.');
  let addresses;
  if (net.isIP(host)) addresses = [{address: host}];
  else {
    try { addresses = await dns.lookup(host, {all: true, verbatim: true}); }
    catch { throw new Error('Could not resolve the URL hostname.'); }
  }
  if (!addresses.length || addresses.some(item => isPrivateAddress(item.address))) throw new Error('URL must resolve only to public IP addresses.');
  url.hash = '';
  return url.toString();
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
  for (let redirects = 0; redirects <= 5; redirects++) {
    currentUrl = await validatePublicHttpsUrl(currentUrl);
    const response = await fetch(currentUrl, {redirect: 'manual', signal: AbortSignal.timeout(Number(process.env.REMOTE_FETCH_TIMEOUT_MS || 20 * 60 * 1000))});
    if ([301,302,303,307,308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location || redirects === 5) throw new Error('Remote file URL redirected too many times.');
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }
    if (!response.ok || !response.body) throw new Error(`Remote file server returned HTTP ${response.status}.`);
    const declared = Number(response.headers.get('content-length') || 0);
    if (declared > maxBytes) throw new Error(`Remote ${path.extname(destination).slice(1).toUpperCase()} exceeds the allowed size.`);
    let received = 0;
    const counter = new Transform({transform(chunk, _encoding, callback) {
      received += chunk.length;
      if (received > maxBytes) return callback(new Error('Remote file exceeded its allowed size while downloading.'));
      onProgress(received, declared || null);
      callback(null, chunk);
    }});
    await pipeline(Readable.fromWeb(response.body), counter, fs.createWriteStream(destination, {flags: 'wx'}));
    if (declared && received !== declared) throw new Error('Remote file download ended before the declared size was received.');
    if (received < 1) throw new Error('Remote file was empty.');
    return received;
  }
  throw new Error('Remote file URL could not be fetched.');
}
app.get('/health', (_req, res) => res.status(200).json({
  ok: true,
  service: 'xsigner',
  signer: 'zsign',
  signerPath: SIGNER,
  signerPresent: fs.existsSync(SIGNER),
  storageConfigured: storageConfigured(),
  encryptionConfigured: Boolean(JOB_ENCRYPTION_KEY),
  recaptchaConfigured: Boolean(RECAPTCHA_SECRET_KEY),
  diskPath: ROOT
}));
app.get('/api/config', (req, res) => res.set('Cache-Control', 'private, no-store').json({
  maxIpaBytes: MAX_IPA_BYTES,
  maxSmallFileBytes: MAX_SMALL_FILE_BYTES,
  partSizeBytes: PART_SIZE,
  publicOrigin: PUBLIC_ORIGIN || null,
  recaptchaSiteKey: '6Lfg6_gtAAAAAI9zK0Uvquy2dG2Qk7op92wVzXVH',
  ownerApiVisible: isOwnerRequest(req)
}));

app.get('/api/owner/discord-api-docs', (req, res) => {
  if (!isOwnerRequest(req)) return res.status(404).json({error: 'Not found.'});
  const origin = (PUBLIC_ORIGIN || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
  const example = [
    `curl -X POST \\`,
    `  -F 'ipaUrl=https://files.example.com/app.ipa' \\`,
    `  -F 'p12=@certificate.p12' \\`,
    `  -F 'mobileprovision=@profile.mobileprovision' \\`,
    `  -F 'password=YOUR_P12_PASSWORD' \\`,
    `  -F 'appName=Example App' \\`,
    `  -F 'bundleId=com.example.app' \\`,
    `  -F 'bundleVersion=1.0' \\`,
    `  -F 'icon=@icon.png' \\`,
    `  -F 'deb=@tweak.deb' \\`,
    `  -F 'dylib=@tweak.dylib' \\`,
    `  '${origin}/sign'`
  ].join('\n');
  res.set('Cache-Control', 'private, no-store').json({
    title: 'Discord bot signing API', endpoint: `${origin}/sign`, method: 'POST',
    contentType: 'multipart/form-data',
    auth: 'No API key and no owner-IP restriction on /sign. The endpoint is public and rate-limited per source IP. Only ipaUrl can be a URL; all signing assets are uploaded as files.',
    fields: [
      {name:'ipa',type:'file',required:'Required unless ipaUrl is supplied',description:'Source .ipa file. Upload this file or use ipaUrl, but not both.'},
      {name:'ipaUrl',type:'HTTPS URL',required:'Optional alternative to ipa file',description:'Public HTTPS URL for the source IPA. This is the only URL field accepted by /sign.'},
      {name:'p12',type:'file',required:true,description:'Signing certificate file (.p12 or .pfx). This is a file upload, not a URL.'},
      {name:'mobileprovision',type:'file',required:true,description:'Apple mobileprovision profile file. This is a file upload, not a URL.'},
      {name:'password',type:'text',required:false,description:'P12 password; omit or use an empty string if unencrypted.'},
      {name:'icon',type:'file',required:false,description:'Optional PNG icon file applied during signing.'},
      {name:'deb',type:'file',required:false,description:'Optional .deb tweak package; contained .dylib files are extracted and injected.'},
      {name:'dylib',type:'file',required:false,description:'Optional .dylib file to inject and re-sign. May be supplied alongside deb.'},
      {name:'appName',type:'text',required:false,description:'Optional display-name override (also accepted as bundleName).'},
      {name:'bundleId',type:'text',required:false,description:'Optional bundle ID override.'},
      {name:'bundleVersion',type:'text',required:false,description:'Optional version override.'},
      {name:'injectExtensions',type:'boolean',required:false,description:'Set to true to also inject tweaks into app extensions.'}
    ],
    example,
    response: JSON.stringify({ok:true,jobId:'<job-uuid>',jobToken:'<bearer-token>',status:'queued',statusUrl:'/api/jobs/<job-uuid>?after=0',downloadUrlEndpoint:'/api/jobs/<job-uuid>/download-url',otaUrlEndpoint:'/api/jobs/<job-uuid>/ota-url'},null,2),
    polling: `curl -H "Authorization: Bearer JOB_TOKEN" "${origin}/api/jobs/JOB_ID?after=0"`,
    download: `curl -X POST -H "Authorization: Bearer JOB_TOKEN" -H "Content-Type: application/json" -d '{}' "${origin}/api/jobs/JOB_ID/download-url"`,
    ota: `curl -X POST -H "Authorization: Bearer JOB_TOKEN" -H "Content-Type: application/json" -d '{}' "${origin}/api/jobs/JOB_ID/ota-url"`
  });
});

app.post('/api/jobs', createLimiter, async (req, res) => {
  if (!storageConfigured()) return res.status(503).json({error: 'Tigris storage is not configured. Add the required AWS/S3 environment variables in Render.'});
  if (!JOB_ENCRYPTION_KEY) return res.status(503).json({error: 'The job encryption key is not configured in Render.'});
  const provided = req.body?.files;
  if (!provided || typeof provided !== 'object') return res.status(400).json({error: 'File metadata is required.'});
  const captchaToken = typeof req.body?.captchaToken === 'string' ? req.body.captchaToken.trim() : '';
  if (!captchaToken) return res.status(400).json({error: 'Complete reCAPTCHA before uploading files.'});
  try {
    // Verify Google's single-use token immediately before creating this job. This avoids
    // a separate in-memory pass that could be lost on restarts or fail on proxy-IP normalization.
    await verifyGoogleCaptcha(captchaToken, req);
  } catch (error) {
    return res.status(error.status || 503).json({error: error.status ? messageOf(error) : 'Google reCAPTCHA is temporarily unavailable. Please retry.'});
  }
  const ipaUrlRaw = clampText(req.body?.ipaUrl || req.body?.ipa_url || req.body?.urls?.ipa, 4096);
  let remoteIpaUrl = '';
  if (ipaUrlRaw) { try { remoteIpaUrl = await validatePublicHttpsUrl(ipaUrlRaw); } catch (error) { return res.status(400).json({error: `Invalid IPA URL: ${messageOf(error)}`}); } }
  const specs = {
    ipa: {ext: '.ipa', max: MAX_IPA_BYTES, required: true},
    certificate: {exts: ['.p12', '.pfx'], max: MAX_SMALL_FILE_BYTES, required: true},
    profile: {ext: '.mobileprovision', max: MAX_SMALL_FILE_BYTES, required: true},
    icon: {ext: '.png', max: MAX_SMALL_FILE_BYTES, required: false},
    dylib: {ext: '.dylib', max: 128 * 1024 * 1024, required: false},
    deb: {ext: '.deb', max: 256 * 1024 * 1024, required: false}
  };
  const normalized = {};
  for (const kind of Object.keys(specs)) {
    const item = provided[kind];
    if ((!item || typeof item !== 'object') && kind === 'ipa' && remoteIpaUrl) {
      normalized[kind] = {name: remoteFilename(remoteIpaUrl, 'ipa'), size: null, contentType: 'application/octet-stream', sourceUrl: remoteIpaUrl};
      continue;
    }
    if (!item || typeof item !== 'object') {
      if (specs[kind].required) return res.status(400).json({error: `Missing ${kind} file${kind === 'ipa' ? ' or public HTTPS IPA URL' : ''}.`});
      continue;
    }
    const name = clampText(item.name, 240);
    const size = Number(item.size);
    if (!name || !Number.isSafeInteger(size) || size < 1 || size > specs[kind].max) {
      return res.status(413).json({error: `${kind} file is empty or exceeds the allowed size.`});
    }
    const ext = path.extname(name).toLowerCase();
    const validExt = specs[kind].ext ? ext === specs[kind].ext : specs[kind].exts.includes(ext);
    if (!validExt) return res.status(400).json({error: `Invalid ${kind} file type.`});
    normalized[kind] = {name, size, contentType: clampText(item.type, 120) || 'application/octet-stream'};
  }
  const id = newId();
  const token = crypto.randomBytes(32).toString('base64url');
  const manifest = {
    id, tokenHash: hashToken(token).toString('hex'), source: 'web', captchaVerifiedAt: Date.now(),
    status: 'creating_uploads', phase: 'preparing', progress: 0,
    createdAt: Date.now(), updatedAt: Date.now(),
    uploads: {}, settings: null, passwordCipher: null,
    resultKey: null, resultSize: null, error: null, logs: [], logSequence: 0,
    otaTokenHash: null, otaExpiresAt: null, otaMetadata: null
  };
  try {
    for (const kind of Object.keys(specs)) {
      const metadata = normalized[kind];
      // Optional uploads (icon, dylib, deb) are absent unless selected.
      // Do not attempt to create a multipart upload for a missing file.
      if (!metadata) continue;
      if (metadata.sourceUrl) {
        manifest.uploads[kind] = makeRemoteUpload(kind, metadata.sourceUrl, metadata.name);
        continue;
      }
      const key = `uploads/${id}/${kind}${path.extname(metadata.name).toLowerCase()}`;
      const result = await getS3().send(new CreateMultipartUploadCommand({
        Bucket: BUCKET, Key: key, ContentType: metadata.contentType,
        Metadata: {jobid: id, kind}
      }));
      manifest.uploads[kind] = {
        key, uploadId: result.UploadId, filename: metadata.name,
        contentType: metadata.contentType, expectedSize: metadata.size,
        partCount: Math.ceil(metadata.size / PART_SIZE), completed: false, actualSize: null
      };
    }
    manifest.status = 'uploading';
    manifest.phase = 'uploading';
    await putManifest(manifest);
    res.status(201).json({jobId: id, jobToken: token, partSizeBytes: PART_SIZE, files: Object.fromEntries(Object.entries(manifest.uploads).map(([kind, value]) => [kind, {partCount: value.partCount, size: value.expectedSize}]))});
  } catch (error) {
    await cleanupInputs(manifest).catch(() => {});
    await fsp.rm(localManifestPath(id), {force: true}).catch(() => {});
    manifestCache.delete(id);
    console.error('job creation failed:', JSON.stringify({
      message: messageOf(error),
      name: error?.name || null,
      code: error?.Code || error?.code || null,
      httpStatusCode: error?.$metadata?.httpStatusCode || null,
      requestId: error?.$metadata?.requestId || null
    }));
    res.status(503).json({error: `Could not start a Tigris upload. Check the bucket, credentials, and permissions. (${messageOf(error)})`});
  }
});

app.post('/api/jobs/:id/part-urls', partLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  const kind = req.body?.kind;
  const upload = manifest.uploads?.[kind];
  const partNumbers = req.body?.partNumbers;
  if (!upload || upload.completed || manifest.status !== 'uploading') return res.status(409).json({error: 'This file is not awaiting upload.'});
  if (!Array.isArray(partNumbers) || partNumbers.length < 1 || partNumbers.length > 16) return res.status(400).json({error: 'Request between 1 and 16 part numbers at a time.'});
  const nums = [...new Set(partNumbers.map(Number))];
  if (nums.length !== partNumbers.length || nums.some(n => !Number.isInteger(n) || n < 1 || n > upload.partCount)) return res.status(400).json({error: 'Invalid multipart part numbers.'});
  try {
    const urls = await Promise.all(nums.map(async partNumber => ({partNumber, url: await signPartUrl(upload, partNumber)})));
    res.set('Cache-Control', 'no-store').json({urls});
  } catch (error) {
    console.error('presign part failed:', messageOf(error));
    res.status(503).json({error: 'Could not authorize this upload part.'});
  }
});

app.post('/api/jobs/:id/complete-upload', partLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  const kind = req.body?.kind;
  const upload = manifest.uploads?.[kind];
  const parts = req.body?.parts;
  if (!upload || upload.completed || manifest.status !== 'uploading') return res.status(409).json({error: 'This file is not awaiting completion.'});
  if (!Array.isArray(parts) || parts.length !== upload.partCount) return res.status(400).json({error: 'The uploaded part list is incomplete.'});
  const normalized = [];
  for (let i = 0; i < parts.length; i++) {
    const partNumber = Number(parts[i]?.partNumber);
    const rawEtag = String(parts[i]?.etag || '');
    if (partNumber !== i + 1 || !/^"?[a-fA-F0-9-]+"?$/.test(rawEtag)) return res.status(400).json({error: 'Multipart part list is invalid.'});
    normalized.push({PartNumber: partNumber, ETag: rawEtag.startsWith('"') ? rawEtag : `"${rawEtag}"`});
  }
  try {
    await getS3().send(new CompleteMultipartUploadCommand({
      Bucket: BUCKET, Key: upload.key, UploadId: upload.uploadId,
      MultipartUpload: {Parts: normalized}
    }));
    // Presigned part URLs bind each part's Content-Length; avoid an additional Class B HEAD read.
    upload.completed = true;
    upload.actualSize = upload.expectedSize;
    upload.uploadId = null;
    const allComplete = Object.values(manifest.uploads).every(value => value.completed);
    if (allComplete) { manifest.status = 'ready'; manifest.phase = 'ready_to_sign'; manifest.progress = 64; }
    await putManifest(manifest);
    res.json({ok: true, kind, completed: true, allComplete});
  } catch (error) {
    console.error('complete upload failed:', messageOf(error));
    res.status(400).json({error: 'Tigris could not finalize this upload. Retry or start the upload again.'});
  }
});

app.post('/api/jobs/:id/sign', actionLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  if (manifest.status !== 'ready' || !['ipa', 'certificate', 'profile'].every(kind => manifest.uploads?.[kind]?.completed)) {
    return res.status(409).json({error: 'Upload the IPA, P12, and mobileprovision before signing.'});
  }
  // Website requests must pass server-verified CAPTCHA before any upload begins.
  // /sign is a separately rate-limited public bot endpoint; it accepts uploaded assets and an optional IPA URL.
  if (manifest.source !== 'api' && !manifest.captchaVerifiedAt) return res.status(403).json({error: 'Complete reCAPTCHA before signing.'});
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (password.length > 2048) return res.status(400).json({error: 'P12 password is too long.'});
  const bundleId = clampText(req.body?.bundleId, 200);
  if (bundleId && !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId)) return res.status(400).json({error: 'Bundle ID format is invalid.'});
  const bundleName = clampText(req.body?.bundleName, 200);
  const bundleVersion = clampText(req.body?.bundleVersion, 100);
  if (bundleVersion && !/^[A-Za-z0-9._+-]+$/.test(bundleVersion)) return res.status(400).json({error: 'Version format is invalid.'});
  try {
    manifest.settings = {bundleId, bundleName, bundleVersion, injectExtensions: req.body?.injectExtensions === true};
    manifest.passwordCipher = encryptPassword(password);
    manifest.status = 'queued'; manifest.phase = 'queued'; manifest.progress = 64; manifest.error = null;
    appendJobLog(manifest, 'Job queued. Waiting for a zsign worker.', 'system', password);
    await flushManifest(manifest);
    enqueue(manifest.id);
    res.status(202).json({ok: true, jobId: manifest.id, status: 'queued'});
  } catch (error) {
    console.error('could not queue signing:', messageOf(error));
    res.status(503).json({error: 'Could not queue this signing job. Check the server encryption key and storage.'});
  }
});

const publicSignLimiter = rateLimit({windowMs: 15 * 60_000, limit: 6, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many public signing requests from this IP. Retry later.'}});
app.post('/sign', publicSignLimiter, apiSignUpload, async (req, res) => {
  const body = req.body || {};
  const files = req.files || {};
  const file = field => Array.isArray(files[field]) ? files[field][0] : null;
  const ipaFile = file('ipa');
  const p12File = file('p12');
  const profileFile = file('mobileprovision');
  const iconFile = file('icon');
  const debFile = file('deb');
  const dylibFile = file('dylib');
  const localApiFiles = [ipaFile, p12File, profileFile, iconFile, debFile, dylibFile].filter(Boolean);
  let manifest = null;
  let password = '';

  try {
    if (!storageConfigured()) return res.status(503).json({error: 'Tigris storage is not configured.'});
    if (!JOB_ENCRYPTION_KEY) return res.status(503).json({error: 'Signing job encryption is not configured.'});

    const rawIpaUrl = clampText(body.ipaUrl, 4096);
    // ipaUrl is the only URL accepted for source material. Certificates and profiles must be uploaded files.
    if (body.p12Url || body.p12_url || body.certificateUrl || body.mobileprovisionUrl || body.mobileprovision_url || body.profileUrl || body.profile_url) {
      return res.status(400).json({error: 'Only ipaUrl may be provided as a URL. Upload p12 and mobileprovision as files.'});
    }
    if (ipaFile && rawIpaUrl) return res.status(400).json({error: 'Provide either the ipa file or ipaUrl, not both.'});
    if (!ipaFile && !rawIpaUrl) return res.status(400).json({error: 'Provide an ipa file or ipaUrl.'});
    if (!p12File || !profileFile) return res.status(400).json({error: 'Upload required files using the p12 and mobileprovision fields.'});

    let ipaUrl = '';
    if (rawIpaUrl) {
      try { ipaUrl = await validatePublicHttpsUrl(rawIpaUrl); }
      catch (error) { throw Object.assign(new Error(`Invalid IPA URL: ${messageOf(error)}`, {cause: error}), {status: 400}); }
    }
    password = typeof body.password === 'string' ? body.password : '';
    if (password.length > 2048) return res.status(400).json({error: 'P12 password is too long.'});
    const bundleId = clampText(body.bundleId || body.bundle_id, 200);
    if (bundleId && !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId)) return res.status(400).json({error: 'Bundle ID format is invalid.'});
    const bundleName = clampText(body.appName || body.app_name || body.bundleName || body.bundle_name, 200);
    const bundleVersion = clampText(body.bundleVersion || body.bundle_version || body.version, 100);
    if (bundleVersion && !/^[A-Za-z0-9._+-]+$/.test(bundleVersion)) return res.status(400).json({error: 'Version format is invalid.'});
    const injectExtensions = body.injectExtensions === true || ['true', '1', 'yes'].includes(String(body.injectExtensions || '').trim().toLowerCase());

    const id = newId();
    const token = crypto.randomBytes(32).toString('base64url');
    manifest = {
      id, tokenHash: hashToken(token).toString('hex'), source: 'api', status: 'creating_uploads', phase: 'preparing', progress: 0,
      createdAt: Date.now(), updatedAt: Date.now(), uploads: {},
      settings: {bundleId, bundleName, bundleVersion, injectExtensions},
      passwordCipher: encryptPassword(password), resultKey: null, resultSize: null, resultExpiresAt: null,
      error: null, logs: [], logSequence: 0, otaTokenHash: null, otaExpiresAt: null, otaMetadata: null
    };

    if (ipaUrl) {
      manifest.uploads.ipa = makeRemoteUpload('ipa', ipaUrl);
      appendJobLog(manifest, 'API request accepted. IPA will be fetched from the supplied public HTTPS URL.', 'system', password);
    }
    const uploadMap = [
      ['p12', 'certificate'], ['mobileprovision', 'profile'], ['icon', 'icon'], ['deb', 'deb'], ['dylib', 'dylib'],
      ...(!ipaUrl && ipaFile ? [['ipa', 'ipa']] : [])
    ];
    for (const [fieldName, kind] of uploadMap) {
      const source = file(fieldName);
      if (!source) continue;
      const extension = path.extname(source.originalname).toLowerCase();
      const key = `uploads/${id}/${kind}${extension}`;
      const contentType = source.mimetype || 'application/octet-stream';
      appendJobLog(manifest, `Uploading API ${kind} file to private Tigris storage (${formatBytesSafe(source.size)}).`, 'system', password);
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
    manifest.status = 'queued'; manifest.phase = 'queued'; manifest.progress = 64;
    manifestCache.set(manifest.id, manifest);
    appendJobLog(manifest, 'Discord API signing request accepted. No API key or IP allowlist is required; requests are rate-limited per IP.', 'system', password);
    await flushManifest(manifest);
    enqueue(manifest.id);
    const origin = (PUBLIC_ORIGIN || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
    return res.status(202).set('Cache-Control', 'no-store').json({ok: true, jobId: manifest.id, jobToken: token, status: 'queued', statusUrl: `${origin}/api/jobs/${manifest.id}?after=0`, downloadUrlEndpoint: `${origin}/api/jobs/${manifest.id}/download-url`, otaUrlEndpoint: `${origin}/api/jobs/${manifest.id}/ota-url`});
  } catch (error) {
    console.error('public /sign request failed:', messageOf(error));
    if (manifest) {
      for (const upload of Object.values(manifest.uploads || {})) if (upload?.key) await removeObject(upload.key);
      if (manifest.resultKey) await removeObject(manifest.resultKey);
      manifest.passwordCipher = null;
      await fsp.rm(localManifestPath(manifest.id), {force: true}).catch(() => {});
      manifestCache.delete(manifest.id);
    }
    if (!res.headersSent) return res.status(error?.status || 503).json({error: error?.status ? messageOf(error) : 'Could not queue the signing request. Check object storage and encryption configuration.'});
  } finally {
    password = '';
    await Promise.all(localApiFiles.map(source => fsp.rm(source.path, {force: true}).catch(() => {})));
  }
});

app.get('/api/jobs/:id', pollLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  const after = Math.max(0, Number.parseInt(req.query.after || '0', 10) || 0);
  res.set('Cache-Control', 'no-store').json({
    id: manifest.id, status: manifest.status, phase: manifest.phase,
    progress: Number(manifest.progress || 0), error: manifest.status === 'failed' ? manifest.error : null,
    resultSize: manifest.status === 'completed' ? manifest.resultSize : null,
    appName: manifest.otaMetadata?.appName || manifest.settings?.bundleName || null,
    logSequence: Number(manifest.logSequence || 0),
    logs: (manifest.logs || []).filter(entry => Number(entry.id) > after).slice(-120)
  });
});

app.post('/api/jobs/:id/download-url', actionLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  if (manifest.status !== 'completed') return res.status(409).json({error: 'Signed IPA is not ready yet.'});
  await expireSignedResultIfNeeded(manifest);
  if (!manifest.resultKey) return res.status(410).json({error: 'This signed IPA expired and was deleted after 10 minutes. Sign the app again to create a new download.'});
  const remainingSeconds = Math.floor((Number(manifest.resultExpiresAt || (Number(manifest.completedAt || Date.now()) + SIGNED_IPA_RETENTION_MS)) - Date.now()) / 1000);
  if (remainingSeconds < 1) return res.status(410).json({error: 'This signed IPA has expired. Sign the app again to create a new download.'});
  const expiresIn = Math.max(1, Math.min(600, remainingSeconds));
  try {
    const url = await getSignedUrl(getS3(), new GetObjectCommand({
      Bucket: BUCKET, Key: manifest.resultKey,
      ResponseContentDisposition: 'attachment; filename="signed.ipa"',
      ResponseContentType: 'application/octet-stream'
    }), {expiresIn});
    res.set('Cache-Control', 'no-store').json({url, expiresIn});
  } catch (error) {
    console.error('download presign failed:', messageOf(error));
    res.status(503).json({error: 'Could not create the download link. Check object storage configuration and try again shortly.'});
  }
});

app.post('/api/jobs/:id/ota-url', actionLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  if (manifest.status !== 'completed') return res.status(409).json({error: 'Signed IPA is not ready for OTA installation.'});
  await expireSignedResultIfNeeded(manifest);
  if (!manifest.resultKey) return res.status(410).json({error: 'This signed IPA expired and was deleted after 10 minutes. Sign the app again for a new OTA link.'});
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
      expiresAt: manifest.otaExpiresAt
    });
  } catch (error) {
    console.error('OTA link generation failed:', messageOf(error));
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
    console.error('OTA manifest failed:', messageOf(error));
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
function safeTerminalLine(value, passwordForRedaction = '') {
  let line = String(value || '').replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '');
  if (passwordForRedaction) line = line.split(passwordForRedaction).join('[REDACTED]');
  return line.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, 900);
}
function appendJobLog(manifest, message, stream = 'system', passwordForRedaction = '') {
  const clean = safeTerminalLine(message, passwordForRedaction);
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
      const redact = text => passwordForRedaction ? text.split(passwordForRedaction).join('[REDACTED]') : text;
      resolve({code, timedOut, out: redact(out), err: redact(err)});
    });
  });
}

const pendingQueue = [];
const queuedIds = new Set();
const activeIds = new Set();
let pumping = false;
function enqueue(id) {
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
    manifest.status = 'signing'; manifest.phase = 'downloading'; manifest.progress = Math.max(64, Number(manifest.progress || 0)); manifest.error = null;
    manifest.logs ||= []; manifest.logSequence = Number(manifest.logSequence || 0);
    appendJobLog(manifest, 'Worker started. Preparing local signing workspace.', 'system', password);
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
        appendJobLog(manifest, `Downloading ${kind} from the supplied HTTPS URL (${upload.filename}) into temporary signing workspace.`, 'system', password);
        let lastLoggedPercent = -10;
        const remoteIndex = Object.keys(manifest.uploads).indexOf(kind);
        const remoteCount = Math.max(1, Object.values(manifest.uploads).filter(value => value.sourceUrl).length);
        const downloadedSize = await downloadRemoteToFile(upload.sourceUrl, local[kind], Number(upload.maxBytes || (kind === 'ipa' ? MAX_IPA_BYTES : MAX_SMALL_FILE_BYTES)), (loaded, total) => {
          if (total && total > 0) {
            const pct = Math.floor(100 * loaded / total);
            manifest.progress = Math.max(Number(manifest.progress || 0), Math.min(70, 64 + Math.floor(6 * (remoteIndex + loaded / total) / remoteCount)));
            if (pct >= lastLoggedPercent + 10 || pct === 100) { lastLoggedPercent = Math.floor(pct / 10) * 10; appendJobLog(manifest, `${kind.toUpperCase()} URL download: ${pct}% (${formatBytesSafe(loaded)} / ${formatBytesSafe(total)}).`, 'system', password); }
          } else if (loaded > 0 && loaded % (10 * 1024 * 1024) < 1024 * 1024) {
            appendJobLog(manifest, `${kind.toUpperCase()} URL download: ${formatBytesSafe(loaded)} received (server did not provide total size).`, 'system', password);
          }
          scheduleManifestFlush(manifest);
        });
        upload.expectedSize = downloadedSize;
        upload.actualSize = downloadedSize;
      } else {
        appendJobLog(manifest, `Downloading ${kind} (${upload.expectedSize} bytes) from private Tigris storage.`, 'system', password);
        let lastMilestone = -10;
        let downloadedForThisFile = 0;
        await writeS3ObjectToFile(upload.key, local[kind], bytes => {
          downloadedInputBytes += bytes;
          downloadedForThisFile += bytes;
          if (totalInputBytes > 0) manifest.progress = Math.max(Number(manifest.progress || 0), Math.min(70, 64 + Math.floor(6 * downloadedInputBytes / totalInputBytes)));
          const pct = upload.expectedSize ? Math.floor(100 * downloadedForThisFile / upload.expectedSize) : 0;
          if (pct >= lastMilestone + 10 || pct === 100) { lastMilestone = Math.floor(pct / 10) * 10; appendJobLog(manifest, `${kind.toUpperCase()} Tigris download: ${pct}% (${formatBytesSafe(downloadedForThisFile)} / ${formatBytesSafe(upload.expectedSize)}).`, 'system', password); }
          scheduleManifestFlush(manifest);
        });
      }
      const info = await fsp.stat(local[kind]);
      if (upload.expectedSize && info.size !== upload.expectedSize) throw new Error(`Downloaded ${kind} size verification failed.`);
      appendJobLog(manifest, `Verified ${kind} on the signing worker (${info.size} bytes).`, 'system', password);
      await flushManifest(manifest);
    }
    const inputMetadata = await readIpaMetadata(local.ipa).catch(error => {
      appendJobLog(manifest, `Could not read IPA metadata automatically: ${messageOf(error)}`, 'stderr', password);
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
      appendJobLog(manifest, 'Extracting the uploaded .deb package to find injectable .dylib files.', 'system', password);
      await runCommand('dpkg-deb', ['-x', local.deb, extractedDeb], {cwd: workDir, timeout: 120_000});
      const foundDylibs = await findFilesByExtension(extractedDeb, '.dylib');
      if (foundDylibs.length === 0) throw new Error('The uploaded .deb contains no .dylib files to inject. Upload a tweak package that contains a compatible dylib.');
      if (foundDylibs.length > 8) throw new Error('The uploaded .deb contains more than 8 dylib files. Please use a smaller package or upload a specific .dylib.');
      dylibsToInject.push(...foundDylibs);
      appendJobLog(manifest, `Found ${foundDylibs.length} dylib file(s) in the .deb package.`, 'system', password);
    }
    manifest.phase = 'signing'; manifest.progress = 70;
    appendJobLog(manifest, 'Starting upstream zsign CLI (version 1.1.2 build target).', 'system', password);
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
    try {
      result = await spawnSigner(args, workDir, password, (line, stream) => {
        const clean = safeTerminalLine(line, password);
        if (!clean) return;
        const lower = clean.toLowerCase();
        if (lower.includes('>>> archiving:') && !archivingActive) {
          archivingActive = true;
          manifest.phase = 'archiving';
          manifest.progress = Math.max(Number(manifest.progress || 0), 88);
          appendJobLog(manifest, 'Archiving the signed IPA: writing the final package. Large apps may take a while; zsign is still working.', 'system', password);
          archiveHeartbeat = setInterval(() => {
            if (manifest.phase !== 'archiving') return stopArchiveHeartbeat();
            appendJobLog(manifest, 'Still archiving the IPA. The final archive is being written; this step can take several minutes for large apps.', 'system', password);
            manifest.progress = Math.min(90, Math.max(88, Number(manifest.progress || 0) + 1));
            scheduleManifestFlush(manifest);
          }, 10_000);
          archiveHeartbeat.unref?.();
        }
        appendJobLog(manifest, clean, stream, password);
        updateProgressFromZsignLine(manifest, clean);
        if (lower.includes('>>> archive ok!') || lower.includes('>>> done.')) {
          stopArchiveHeartbeat();
          if (manifest.phase === 'archiving') manifest.phase = 'signing';
        }
        scheduleManifestFlush(manifest);
      });
    } finally {
      stopArchiveHeartbeat();
    }
    await flushManifest(manifest);
    if (result.timedOut) throw new Error('Signing exceeded the configured time limit. Try a smaller IPA or increase SIGN_TIMEOUT_MS.');
    const outputStat = await fsp.stat(output).catch(() => null);
    if (result.code !== 0 || !outputStat?.isFile() || outputStat.size < 1) {
      const detail = (result.err || result.out || 'zsign reported a failure').slice(-2500);
      throw new Error(password ? detail.split(password).join('[REDACTED]') : detail);
    }
    manifest.phase = 'uploading_result'; manifest.progress = Math.max(91, Number(manifest.progress || 0));
    manifest.resultKey = `signed/${id}/signed.ipa`;
    appendJobLog(manifest, `zsign exited successfully. Signed IPA size: ${outputStat.size} bytes. Uploading result to private storage.`, 'system', password);
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
          appendJobLog(manifest, `Tigris result upload: ${pct}% (${formatBytesSafe(loaded)} / ${formatBytesSafe(total)}).`, 'system', password);
        }
      }
      scheduleManifestFlush(manifest);
    });
    await uploader.done();
    await flushManifest(manifest);
    manifest.resultSize = outputStat.size;
    manifest.completedAt = Date.now();
    manifest.resultExpiresAt = manifest.completedAt + SIGNED_IPA_RETENTION_MS;
    await cleanupInputs(manifest, false);
    manifest.passwordCipher = null;
    manifest.status = 'completed'; manifest.phase = 'completed'; manifest.progress = 100;
    manifest.error = null;
    appendJobLog(manifest, 'Result uploaded. Temporary source files and certificate material will now be removed.', 'system', password);
    password = '';
    await flushManifest(manifest);
  } catch (error) {
    const rawError = messageOf(error);
    const safeError = safeTerminalLine(rawError, password).slice(0, 2000) || 'Signing job failed.';
    console.error(`signing job ${id} failed:`, safeError);
    if (manifest) {
      appendJobLog(manifest, safeError, 'error', password);
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
  if (!storageConfigured() || !JOB_ENCRYPTION_KEY) return;
  try {
    const keys = await listManifestKeys();
    const now = Date.now();
    for (const key of keys) {
      const id = key.split('/')[1];
      if (!validateId(id) || activeIds.has(id) || queuedIds.has(id)) continue;
      const manifest = await maybeManifest(id);
      if (!manifest) continue;
      if (manifest.status === 'queued') enqueue(id);
      else if (manifest.status === 'signing' && (recoverInterruptedImmediately || now - Number(manifest.updatedAt || 0) > STALE_JOB_MS)) {
        manifest.status = 'queued'; manifest.phase = 'queued';
        manifest.progress = 64; manifest.error = null;
        await putManifest(manifest);
        enqueue(id);
      }
    }
  } catch (error) {
    console.warn('queue recovery unavailable:', messageOf(error));
  }
}
async function cleanupExpiredSignedResults() {
  if (!storageConfigured()) return;
  try {
    const entries = await fsp.readdir(MANIFEST_ROOT, {withFileTypes: true});
    for (const entry of entries) {
      if (!entry.isFile() || !/^[0-9a-f-]{36}\.json$/i.test(entry.name)) continue;
      const id = entry.name.slice(0, -5);
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

// Public NexCerts index proxy. This keeps browser pages on the same origin and
// does not store certificate files or passwords locally on this server.
const listCertificatesHandler = async (req, res) => {
  const allowed = new Set(['all', 'signed', 'revoked', 'missingP12']);
  const status = req.params.status;
  if (!allowed.has(status)) return res.status(400).json({error: 'Status must be all, signed, revoked, or missingP12.'});
  let amount = '';
  if (req.params.amount !== undefined) {
    const count = Number(req.params.amount);
    if (!Number.isInteger(count) || count < 1 || count > 500) return res.status(400).json({error: 'Amount must be an integer from 1 to 500.'});
    amount = `/${count}`;
  }
  try {
    const upstream = await fetch(`${CERT_API_BASE}/list/${status}${amount}`, {headers: {accept: 'application/json'}, signal: AbortSignal.timeout(20_000)});
    const body = await upstream.text();
    res.status(upstream.status).set('Cache-Control', 'public, max-age=60').type('application/json').send(body);
  } catch (error) {
    console.error('NexCerts list proxy failed:', messageOf(error));
    res.status(502).json({error: 'Could not retrieve the certificate list from NexCerts.'});
  }
};
app.get('/api/free-certificates/list/:status', actionLimiter, listCertificatesHandler);
app.get('/api/free-certificates/list/:status/:amount', actionLimiter, listCertificatesHandler);

app.get('/api/free-certificates/download/all.zip', actionLimiter, async (_req, res) => {
  await proxyCertificateDownload('all.zip', null, null, res);
});
app.get('/api/free-certificates/download/missingP12/:id/:file', actionLimiter, async (req, res) => {
  const id = req.params.id;
  const file = req.params.file;
  if (!/^\d+$/.test(id) || !['cert.zip', 'cert.mobileprovision'].includes(file)) return res.status(400).json({error: 'Invalid missing-P12 download request.'});
  await proxyCertificateDownload(id, file, 'missingP12', res);
});
app.get('/api/free-certificates/download/:id/:file', actionLimiter, async (req, res) => {
  const {id, file} = req.params;
  if (!/^\d+$/.test(id) || !['cert.zip', 'cert.p12', 'cert.mobileprovision', 'password.txt', 'password'].includes(file)) return res.status(400).json({error: 'Invalid certificate download request.'});
  await proxyCertificateDownload(id, file, null, res);
});
async function proxyCertificateDownload(idOrAll, file, status, res) {
  try {
    let url;
    if (idOrAll === 'all.zip') url = `${CERT_API_BASE}/download/all.zip`;
    else if (status === 'missingP12') url = `${CERT_API_BASE}/download/missingP12/${encodeURIComponent(idOrAll)}/${encodeURIComponent(file)}`;
    else url = `${CERT_API_BASE}/download/${encodeURIComponent(idOrAll)}/${encodeURIComponent(file)}`;
    const upstream = await fetch(url, {redirect: 'follow', signal: AbortSignal.timeout(90_000)});
    if (!upstream.ok) {
      const body = await upstream.text();
      return res.status(upstream.status).type('application/json').send(body || JSON.stringify({error: 'Certificate file is not available.'}));
    }
    const contentType = upstream.headers.get('content-type') || (file === 'password' ? 'text/plain; charset=utf-8' : 'application/octet-stream');
    res.set('Content-Type', contentType).set('Cache-Control', 'no-store');
    const downloadName = file === 'password' ? `certificate-${idOrAll}-password.txt` : file || 'all-certs.zip';
    if (!contentType.includes('application/json')) res.set('Content-Disposition', `attachment; filename="${downloadName.replace(/[^a-zA-Z0-9._-]/g, '_')}"`);
    if (!upstream.body) return res.status(502).end();
    const reader = upstream.body.getReader();
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      if (!res.write(Buffer.from(value))) await new Promise(resolve => res.once('drain', resolve));
    }
    res.end();
  } catch (error) {
    console.error('NexCerts download proxy failed:', messageOf(error));
    if (!res.headersSent) res.status(502).json({error: 'Could not download the certificate file from NexCerts.'});
    else res.end();
  }
}

app.post('/api/certchecker/checkCert', actionLimiter, (req, res, next) => {
  checkerUpload(req, res, error => error ? next(error) : next());
}, async (req, res) => {
  const p12 = req.files?.p12?.[0];
  const mobileprovision = req.files?.mobileprovision?.[0];
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!p12 && !mobileprovision) return res.status(400).json({error: 'Upload a P12 certificate, a mobileprovision file, or both.'});
  if (p12 && !password) return res.status(400).json({error: 'P12 password is required when a P12 certificate is provided.'});
  try {
    const form = new FormData();
    if (p12) form.append('p12', new Blob([p12.buffer], {type: p12.mimetype || 'application/x-pkcs12'}), path.basename(p12.originalname || 'certificate.p12'));
    if (mobileprovision) form.append('mobileprovision', new Blob([mobileprovision.buffer], {type: mobileprovision.mimetype || 'application/octet-stream'}), path.basename(mobileprovision.originalname || 'profile.mobileprovision'));
    if (p12) form.append('password', password);
    const upstream = await fetch('https://sideloading.net/api/certchecker/checkCert', {method: 'POST', body: form, signal: AbortSignal.timeout(90_000)});
    const body = await upstream.text();
    res.status(upstream.status).set('Cache-Control', 'no-store').type('application/json').send(body);
  } catch (error) {
    console.error('NexCerts certificate check failed:', messageOf(error));
    res.status(502).json({error: 'Certificate checking service is unavailable. Please retry.'});
  } finally {
    if (req.body) req.body.password = '';
  }
});

app.use((error, _req, res, _next) => {
  console.error('request failed:', messageOf(error));
  if (res.headersSent) return;
  if (error?.status) return res.status(error.status).json({error: messageOf(error)});
  if (error?.code === 'LIMIT_FILE_SIZE' || error?.code === 'LIMIT_FILE_COUNT') return res.status(413).json({error: 'Uploaded files exceed the configured upload limit.'});
  if (error?.name === 'MulterError') return res.status(400).json({error: 'Invalid multipart file upload.'});
  res.status(500).json({error: 'Unexpected server error.'});
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`xsigner listening on 0.0.0.0:${PORT}; Tigris configured=${storageConfigured()}`);
  // One best-effort recovery scan per process start. Polling no longer lists/downloads every remote manifest.
  void recoverJobs({recoverInterruptedImmediately: true});
});
const maintenanceIntervalMs = Number(process.env.S3_MAINTENANCE_INTERVAL_MS || 0);
const maintenanceTimer = maintenanceIntervalMs >= 60 * 60_000 ? setInterval(() => { void recoverJobs(); void cleanupExpiredJobs(); }, maintenanceIntervalMs).unref() : null;
const signedResultCleanupTimer = setInterval(() => { void cleanupExpiredSignedResults(); }, SIGNED_IPA_CLEANUP_INTERVAL_MS).unref();
void cleanupExpiredSignedResults();

async function shutdown() {
  if (maintenanceTimer) clearInterval(maintenanceTimer);
  if (signedResultCleanupTimer) clearInterval(signedResultCleanupTimer);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 25_000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
