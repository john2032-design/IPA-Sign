# Optional multi-instance deployment

The default `render.yaml` intentionally remains the working single-service deployment. It does not provision Redis/Valkey and does not turn on background-worker mode automatically. Use this guide only when you explicitly decide to add a shared queue and background worker(s); a Render Key Value resource can add monthly cost.

## Why these settings must change together

The normal deployment has an in-process queue and local job manifests. That mode is intended for one API instance. Multi-instance mode uses BullMQ backed by Render Key Value/Redis, and writes job manifests to the shared Tigris bucket. Do **not** scale the API horizontally with the local queue or `MANIFEST_STORAGE=local`: another instance would not see its manifests or jobs.

## API web service

Keep the existing `xsigner` web service and set:

```text
REDIS_URL=<private connection URL from the Render Key Value resource>
MANIFEST_STORAGE=s3
RUN_SIGNING_WORKER=false
AWS_ENDPOINT_URL_S3=https://t3.storage.dev
AWS_REGION=auto
S3_BUCKET=xsigner
AWS_ACCESS_KEY_ID=<same Tigris access key used by all workers>
AWS_SECRET_ACCESS_KEY=<same Tigris secret used by all workers>
JOB_ENCRYPTION_KEY=<same existing value used by all workers>
```

Keep the existing `PUBLIC_ORIGIN`, `OWNER_IP`, upload/signing limits and result-retention settings. `API_CLIENTS_JSON` is optional. When configured, authenticated-client quotas use Redis atomic counters and are shared across API instances; anonymous and per-IP safety rate limiters still use the HTTP process's standard rate-limit store.

## Background worker service

In Render, create a **Background Worker** from this same repository and Dockerfile. Use the same repository branch, `Dockerfile`, and build context. Start command:

```bash
node server.js
```

Set these variables on each worker:

```text
REDIS_URL=<same private connection URL>
MANIFEST_STORAGE=s3
RUN_SIGNING_WORKER=true
DATA_DIR=/tmp/xsigner-worker
ZSIGN_BIN=/usr/local/bin/zsign
AWS_ENDPOINT_URL_S3=https://t3.storage.dev
AWS_REGION=auto
S3_BUCKET=xsigner
AWS_ACCESS_KEY_ID=<same Tigris access key>
AWS_SECRET_ACCESS_KEY=<same Tigris secret>
JOB_ENCRYPTION_KEY=<same existing value as API service>
MAX_IPA_BYTES=4294967296
PART_SIZE_BYTES=67108864
MAX_CONCURRENT_JOBS=1
SIGN_TIMEOUT_MS=3600000
REMOTE_FETCH_TIMEOUT_MS=3600000
```

Workers do not listen on HTTP ports. Their local work directory is scratch space; uploaded assets, manifests and signed results live in Tigris. Keep `MAX_CONCURRENT_JOBS` conservative because each zsign job can require several times the source IPA's size in working storage.

## Safety checklist before adding replicas

1. Create the private Key Value/Redis resource and verify its internal connection URL from the Render dashboard.
2. Apply the same `REDIS_URL`, `MANIFEST_STORAGE=s3`, Tigris credentials and `JOB_ENCRYPTION_KEY` to the API and all workers.
3. Set `RUN_SIGNING_WORKER=false` on the API, `true` on workers. Do not set `true` on the public web service unless intentionally running combined API+worker mode.
4. Confirm `/healthz/dependencies` reports the required checks ready on the API; submit a test IPA and poll it until completion.
5. Scale one worker at a time and observe queue age, job duration, Tigris errors and worker logs before adding more instances.

BullMQ uses Redis persistence and worker locks/stalled-job recovery. Job manifests must be in S3/Tigris mode when Redis queue mode is enabled; the application fails startup early if `REDIS_URL` is set with local manifest storage. Keep Redis configured with `noeviction` where possible, as BullMQ queue keys must not be evicted under memory pressure.

This optional mode does not add an idempotency key or cancellation endpoint. It intentionally does not change the existing Discord bot contract; submission still returns `202` with `jobId`, `jobToken`, and polling URLs.
