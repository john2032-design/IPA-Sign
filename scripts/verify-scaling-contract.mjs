import assert from 'node:assert/strict';
import fs from 'node:fs';

const server = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const packageJson = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const docker = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const scaling = fs.readFileSync(new URL('../docs/SCALING.md', import.meta.url), 'utf8');
const yaml = fs.readFileSync(new URL('../render.yaml', import.meta.url), 'utf8');

assert(packageJson.dependencies.bullmq, 'BullMQ dependency is required for shared queue mode');
assert(packageJson.dependencies.ioredis, 'ioredis dependency is required for atomic shared quotas');
assert(docker.includes('COPY lib ./lib'), 'Docker image must copy runtime helper modules');
assert(server.includes("import {Queue, Worker} from 'bullmq'"), 'shared queue imports missing');
assert(server.includes("new Queue(QUEUE_NAME"), 'API service must be able to enqueue durable jobs');
assert(server.includes("new Worker(QUEUE_NAME"), 'worker mode must consume shared BullMQ jobs');
assert(server.includes("REDIS_URL requires MANIFEST_STORAGE=s3"), 'shared queue mode must reject local-only manifests');
assert(server.includes('if (isLocalManifestStorage()) {\n    const cached = manifestCache.get(id);'), 'local manifest mode should retain the existing cache path');
assert(server.includes('if (!SHARED_QUEUE_ENABLED) manifestCache.set(id, manifest);'), 'remote-manifest mode must avoid stale per-instance cache reads');
assert(server.includes("process.env.RUN_SIGNING_WORKER !== 'false'"), 'worker activation switch must be present');
assert(server.includes("if (WORKER_ONLY) throw new Error" ) || server.includes("if (WORKER_ONLY && !sharedSigningWorker) throw new Error"), 'worker-only configuration must fail if queue worker is missing');
assert(server.includes("const script = \"local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); end; return count\""), 'client quotas must be shared/atomic with Redis in distributed mode');
assert(readme.includes('RUN_SIGNING_WORKER=true') && readme.includes('MANIFEST_STORAGE=s3'), 'README must document the shared worker configuration');
assert(scaling.includes('Render Key Value') && scaling.includes('JOB_ENCRYPTION_KEY'), 'scaling guide must document Redis wiring and the shared encryption key');
assert(yaml.includes('healthCheckPath: /healthz'), 'default render blueprint must keep the existing health endpoint');
assert(!yaml.includes('type: keyvalue'), 'default blueprint must not provision an extra billable Redis resource automatically');

console.log('Scaling contract checks passed: optional BullMQ queue, shared S3 manifests, distributed client quotas, and safe default deployment.');
