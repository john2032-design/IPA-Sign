import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawn} from 'node:child_process';
import {pipeline} from 'node:stream/promises';
import {
  S3Client, CreateMultipartUploadCommand, UploadPartCommand,
  CompleteMultipartUploadCommand, AbortMultipartUploadCommand,
  PutObjectCommand, GetObjectCommand, HeadObjectCommand,
  DeleteObjectCommand, ListObjectsV2Command
} from '@aws-sdk/client-s3';
import {getSignedUrl} from '@aws-sdk/s3-request-presigner';
import {Upload} from '@aws-sdk/lib-storage';

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 10000);
const ROOT = process.env.DATA_DIR || '/tmp/xsigner-data';
const WORK_ROOT = path.join(ROOT, 'work');
const SIGNER = process.env.RORKSIGN_BIN || '/usr/local/bin/rorksign';
const BUCKET = process.env.B2_BUCKET || '';
const REGION = process.env.B2_REGION || 'us-east-005';
const ENDPOINT = process.env.B2_ENDPOINT || `https://s3.${REGION}.backblazeb2.com`;
const MAX_IPA_BYTES = Number(process.env.MAX_IPA_BYTES || 4294967296);
const MAX_SMALL_FILE_BYTES = 16 * 1024 * 1024;
const PART_SIZE = Number(process.env.PART_SIZE_BYTES || 64 * 1024 * 1024);
const JOB_TTL_MS = Number(process.env.JOB_TTL_HOURS || 24) * 60 * 60 * 1000;
const UPLOAD_TTL_MS = Number(process.env.UPLOAD_TTL_HOURS || 6) * 60 * 60 * 1000;
const STALE_JOB_MS = Number(process.env.STALE_JOB_MINUTES || 45) * 60 * 1000;
const MAX_CONCURRENT_JOBS = Math.max(1, Number(process.env.MAX_CONCURRENT_JOBS || 1));
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || '';
const JOB_ENCRYPTION_KEY = process.env.JOB_ENCRYPTION_KEY || '';

await fsp.mkdir(WORK_ROOT, {recursive: true});

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy: false, crossOriginEmbedderPolicy: false}));
app.use(express.json({limit: '1mb'}));
app.use(express.static(path.join(process.cwd(), 'public'), {maxAge: '1h', etag: true}));

const createLimiter = rateLimit({windowMs: 60_000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many jobs created. Try again in a minute.'}});
const partLimiter = rateLimit({windowMs: 60_000, limit: 240, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many upload requests. Slow down and retry.'}});
const actionLimiter = rateLimit({windowMs: 60_000, limit: 15, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many requests. Try again shortly.'}});
const pollLimiter = rateLimit({windowMs: 60_000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false, message: {error: 'Too many status requests. Slow down briefly.'}});

let s3Client;
function storageConfigured() {
  return Boolean(BUCKET && process.env.B2_KEY_ID && process.env.B2_APPLICATION_KEY && ENDPOINT && REGION);
}
function getS3() {
  if (!storageConfigured()) throw new Error('Backblaze B2 is not configured. Set B2_BUCKET, B2_KEY_ID, and B2_APPLICATION_KEY in Render.');
  if (!s3Client) {
    s3Client = new S3Client({
      region: REGION,
      endpoint: ENDPOINT,
      forcePathStyle: true,
      credentials: {
        accessKeyId: process.env.B2_KEY_ID,
        secretAccessKey: process.env.B2_APPLICATION_KEY
      },
      maxAttempts: 4
    });
  }
  return s3Client;
}
function s3KeyForManifest(id) { return `jobs/${id}/manifest.json`; }
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
function messageOf(error) { return String(error?.message || 'Unexpected error').slice(0, 700); }
function isManifestKey(key) { return typeof key === 'string' && key.startsWith('jobs/') && key.endsWith('/manifest.json'); }

async function putManifest(manifest) {
  manifest.updatedAt = Date.now();
  await getS3().send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: s3KeyForManifest(manifest.id),
    Body: JSON.stringify(manifest),
    ContentType: 'application/json; charset=utf-8',
    CacheControl: 'no-store'
  }));
}
async function getManifest(id) {
  const response = await getS3().send(new GetObjectCommand({Bucket: BUCKET, Key: s3KeyForManifest(id)}));
  const body = await response.Body.transformToString();
  return JSON.parse(body);
}
async function maybeManifest(id) {
  try { return await getManifest(id); }
  catch (error) {
    if (error?.$metadata?.httpStatusCode === 404 || error?.name === 'NoSuchKey' || error?.name === 'NotFound') return null;
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
    return manifest;
  } catch (error) {
    console.error('manifest read failed:', messageOf(error));
    res.status(503).json({error: 'Job storage is temporarily unavailable.'});
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
  const client = getS3();
  const keys = [];
  let token;
  do {
    const page = await client.send(new ListObjectsV2Command({Bucket: BUCKET, Prefix: 'jobs/', ContinuationToken: token, MaxKeys: 1000}));
    for (const obj of page.Contents || []) if (isManifestKey(obj.Key)) keys.push(obj.Key);
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
  return keys;
}
async function removeObject(key) {
  if (!key) return;
  try { await getS3().send(new DeleteObjectCommand({Bucket: BUCKET, Key: key})); }
  catch (error) { console.warn('object cleanup failed:', messageOf(error)); }
}
async function cleanupInputs(manifest, abortOpen = true) {
  const client = getS3();
  for (const upload of Object.values(manifest.uploads || {})) {
    if (!upload) continue;
    if (abortOpen && upload.uploadId && !upload.completed) {
      try { await client.send(new AbortMultipartUploadCommand({Bucket: BUCKET, Key: upload.key, UploadId: upload.uploadId})); }
      catch (error) { /* The multipart upload may already have expired or completed. */ }
    }
    await removeObject(upload.key);
    upload.uploadId = null;
  }
}

app.get('/health', (_req, res) => res.status(200).json({
  ok: true,
  service: 'xsigner',
  signerPresent: fs.existsSync(SIGNER),
  storageConfigured: storageConfigured(),
  encryptionConfigured: Boolean(JOB_ENCRYPTION_KEY),
  diskPath: ROOT
}));
app.get('/api/config', (_req, res) => res.json({
  maxIpaBytes: MAX_IPA_BYTES,
  maxSmallFileBytes: MAX_SMALL_FILE_BYTES,
  partSizeBytes: PART_SIZE,
  publicOrigin: PUBLIC_ORIGIN || null
}));

app.post('/api/jobs', createLimiter, async (req, res) => {
  if (!storageConfigured()) return res.status(503).json({error: 'Backblaze B2 is not configured. Add the required B2 environment variables in Render.'});
  if (!JOB_ENCRYPTION_KEY) return res.status(503).json({error: 'The job encryption key is not configured in Render.'});
  const provided = req.body?.files;
  if (!provided || typeof provided !== 'object') return res.status(400).json({error: 'File metadata is required.'});
  const specs = {
    ipa: {ext: '.ipa', max: MAX_IPA_BYTES},
    certificate: {exts: ['.p12', '.pfx'], max: MAX_SMALL_FILE_BYTES},
    profile: {ext: '.mobileprovision', max: MAX_SMALL_FILE_BYTES}
  };
  const normalized = {};
  for (const kind of Object.keys(specs)) {
    const item = provided[kind];
    if (!item || typeof item !== 'object') return res.status(400).json({error: `Missing ${kind} file.`});
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
    id, tokenHash: hashToken(token).toString('hex'),
    status: 'creating_uploads', phase: 'preparing', progress: 0,
    createdAt: Date.now(), updatedAt: Date.now(),
    uploads: {}, settings: null, passwordCipher: null,
    resultKey: null, resultSize: null, error: null
  };
  try {
    for (const kind of Object.keys(specs)) {
      const metadata = normalized[kind];
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
    await removeObject(s3KeyForManifest(id));
    console.error('job creation failed:', messageOf(error));
    res.status(503).json({error: 'Could not start a Backblaze upload. Check the B2 bucket, credentials, and permissions.'});
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
    const head = await getS3().send(new HeadObjectCommand({Bucket: BUCKET, Key: upload.key}));
    if (Number(head.ContentLength) !== upload.expectedSize) {
      await removeObject(upload.key);
      manifest.status = 'failed'; manifest.phase = 'failed';
      manifest.error = 'Uploaded file size did not match the selected file. Please start a new job.';
      await cleanupInputs(manifest).catch(() => {});
      await putManifest(manifest);
      return res.status(400).json({error: manifest.error});
    }
    upload.completed = true;
    upload.actualSize = Number(head.ContentLength);
    upload.uploadId = null;
    const allComplete = Object.values(manifest.uploads).every(value => value.completed);
    if (allComplete) { manifest.status = 'ready'; manifest.phase = 'ready_to_sign'; manifest.progress = 5; }
    await putManifest(manifest);
    res.json({ok: true, kind, completed: true, allComplete});
  } catch (error) {
    console.error('complete upload failed:', messageOf(error));
    res.status(400).json({error: 'Backblaze could not finalize this upload. Retry or start the upload again.'});
  }
});

app.post('/api/jobs/:id/sign', actionLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  if (manifest.status !== 'ready' || !Object.values(manifest.uploads || {}).every(value => value.completed)) {
    return res.status(409).json({error: 'Upload all three files before signing.'});
  }
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (password.length > 2048) return res.status(400).json({error: 'P12 password is too long.'});
  const bundleId = clampText(req.body?.bundleId, 200);
  if (bundleId && !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId)) return res.status(400).json({error: 'Bundle ID format is invalid.'});
  const bundleName = clampText(req.body?.bundleName, 200);
  const bundleVersion = clampText(req.body?.bundleVersion, 100);
  if (bundleVersion && !/^[A-Za-z0-9._+-]+$/.test(bundleVersion)) return res.status(400).json({error: 'Version format is invalid.'});
  try {
    manifest.settings = {bundleId, bundleName, bundleVersion, sha256Only: req.body?.sha256Only === true};
    manifest.passwordCipher = encryptPassword(password);
    manifest.status = 'queued'; manifest.phase = 'queued'; manifest.progress = 8; manifest.error = null;
    await putManifest(manifest);
    enqueue(manifest.id);
    res.status(202).json({ok: true, jobId: manifest.id, status: 'queued'});
  } catch (error) {
    console.error('could not queue signing:', messageOf(error));
    res.status(503).json({error: 'Could not queue this signing job. Check the server encryption key and storage.'});
  }
});

app.get('/api/jobs/:id', pollLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  res.set('Cache-Control', 'no-store').json({
    id: manifest.id, status: manifest.status, phase: manifest.phase,
    progress: Number(manifest.progress || 0), error: manifest.status === 'failed' ? manifest.error : null,
    resultSize: manifest.status === 'completed' ? manifest.resultSize : null
  });
});

app.post('/api/jobs/:id/download-url', actionLimiter, async (req, res) => {
  const manifest = await authorizedJob(req, res, req.params.id);
  if (!manifest) return;
  if (manifest.status !== 'completed' || !manifest.resultKey) return res.status(409).json({error: 'Signed IPA is not ready yet.'});
  try {
    const url = await getSignedUrl(getS3(), new GetObjectCommand({
      Bucket: BUCKET, Key: manifest.resultKey,
      ResponseContentDisposition: 'attachment; filename="signed.ipa"',
      ResponseContentType: 'application/octet-stream'
    }), {expiresIn: 3600});
    res.set('Cache-Control', 'no-store').json({url, expiresIn: 3600});
  } catch (error) {
    console.error('download presign failed:', messageOf(error));
    res.status(503).json({error: 'Could not create the download link. Try again shortly.'});
  }
});

async function writeB2ObjectToFile(key, destination) {
  const response = await getS3().send(new GetObjectCommand({Bucket: BUCKET, Key: key}));
  await pipeline(response.Body, fs.createWriteStream(destination, {flags: 'wx'}));
}
function spawnSigner(args, cwd, passwordForRedaction) {
  return new Promise((resolve, reject) => {
    const child = spawn(SIGNER, args, {cwd, stdio: ['ignore', 'pipe', 'pipe']});
    let out = '', err = '', outBytes = 0, errBytes = 0;
    const maxCapture = 1024 * 1024;
    child.stdout.on('data', chunk => {
      if (outBytes < maxCapture) { out += chunk.toString(); outBytes += chunk.length; }
    });
    child.stderr.on('data', chunk => {
      if (errBytes < maxCapture) { err += chunk.toString(); errBytes += chunk.length; }
    });
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
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
  const workDir = path.join(WORK_ROOT, id);
  try {
    manifest = await getManifest(id);
    if (manifest.status !== 'queued' && manifest.status !== 'signing') return;
    if (!fs.existsSync(SIGNER)) throw new Error('rork-sign binary is missing from this container.');
    const password = decryptPassword(manifest.passwordCipher);
    manifest.status = 'signing'; manifest.phase = 'downloading'; manifest.progress = 12; manifest.error = null;
    await putManifest(manifest);
    await fsp.rm(workDir, {recursive: true, force: true});
    await fsp.mkdir(workDir, {recursive: true});
    const local = {};
    for (const kind of ['ipa', 'certificate', 'profile']) {
      const upload = manifest.uploads[kind];
      local[kind] = path.join(workDir, `input-${kind}${path.extname(upload.filename).toLowerCase()}`);
      await writeB2ObjectToFile(upload.key, local[kind]);
      const info = await fsp.stat(local[kind]);
      if (info.size !== upload.expectedSize) throw new Error(`Downloaded ${kind} size verification failed.`);
    }
    manifest.phase = 'signing'; manifest.progress = 24;
    await putManifest(manifest);
    const output = path.join(workDir, 'signed.ipa');
    const args = ['-k', local.certificate, '-p', password, '-m', local.profile, '-o', output, local.ipa];
    if (manifest.settings?.bundleId) args.push('-b', manifest.settings.bundleId);
    if (manifest.settings?.bundleName) args.push('-n', manifest.settings.bundleName);
    if (manifest.settings?.bundleVersion) args.push('-r', manifest.settings.bundleVersion);
    if (manifest.settings?.sha256Only) args.push('-2');
    const result = await spawnSigner(args, workDir, password);
    if (result.timedOut) throw new Error('Signing exceeded the time limit. Try a smaller IPA or a larger Render instance.');
    const outputStat = await fsp.stat(output).catch(() => null);
    if (result.code !== 0 || !outputStat?.isFile() || outputStat.size < 1) {
      const detail = (result.err || result.out || 'rork-sign reported a failure').slice(-2500);
      throw new Error(password ? detail.split(password).join('[REDACTED]') : detail);
    }
    manifest.phase = 'uploading_result'; manifest.progress = 82;
    manifest.resultKey = `signed/${id}/signed.ipa`;
    await putManifest(manifest);
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
    await uploader.done();
    manifest.resultSize = outputStat.size;
    await cleanupInputs(manifest, false);
    manifest.passwordCipher = null;
    manifest.status = 'completed'; manifest.phase = 'completed'; manifest.progress = 100;
    manifest.completedAt = Date.now(); manifest.error = null;
    await putManifest(manifest);
  } catch (error) {
    const safeError = messageOf(error).slice(0, 2000);
    console.error(`signing job ${id} failed:`, safeError);
    if (manifest) {
      manifest.status = 'failed'; manifest.phase = 'failed'; manifest.error = safeError;
      manifest.passwordCipher = null;
      await cleanupInputs(manifest, true).catch(() => {});
      if (manifest.resultKey) await removeObject(manifest.resultKey);
      await putManifest(manifest).catch(() => {});
    }
  } finally {
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
        manifest.progress = 8; manifest.error = null;
        await putManifest(manifest);
        enqueue(id);
      }
    }
  } catch (error) {
    console.warn('queue recovery unavailable:', messageOf(error));
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
        await removeObject(key);
      }
    }
  } catch (error) {
    console.warn('expired job cleanup unavailable:', messageOf(error));
  }
}

app.use((error, _req, res, _next) => {
  console.error('request failed:', messageOf(error));
  if (res.headersSent) return;
  res.status(500).json({error: 'Unexpected server error.'});
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`xsigner listening on 0.0.0.0:${PORT}; B2 configured=${storageConfigured()}`);
  void recoverJobs({recoverInterruptedImmediately: true});
});
const recoveryTimer = setInterval(() => void recoverJobs(), 60_000).unref();
const cleanupTimer = setInterval(() => void cleanupExpiredJobs(), 15 * 60_000).unref();

async function shutdown() {
  clearInterval(recoveryTimer); clearInterval(cleanupTimer);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 25_000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
