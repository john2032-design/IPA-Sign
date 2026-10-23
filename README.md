# xsigner — API-only IPA signing service

This project runs an API-only Node.js service on Render. It does not serve a website UI. `POST /sign` (also available as `POST /api/v1/discord/sign`) queues IPA signing through the upstream zsign CLI, stores source/result objects in a private Tigris S3-compatible bucket, and returns temporary download and OTA-install links.

## Endpoints

- `GET /` — JSON service and endpoint summary (not HTML).
- `GET /doc` — owner-IP-restricted HTML documentation page; `GET /doc/openapi.json` serves the equivalent OpenAPI JSON. Both use `OWNER_IP` (fallback `XSIGNER_OWNER_IP`, then `168.91.23.165`). The `/sign` API itself remains public and has no owner-IP restriction.
- `GET /healthz` — Render runtime readiness probe; returns HTTP 200 only when zsign, Tigris configuration, and job encryption are available, otherwise HTTP 503. The Render service health check is configured to `/healthz`.
- `GET /health` — backwards-compatible alias of `/healthz`.
- `GET /healthz/dependencies` — cached deeper diagnostic probe that attempts a bounded zsign version check, Tigris bucket check, writable workspace check and Redis ping when shared queue mode is enabled. Returns 200 when ready or 503 when a dependency check fails; details intentionally expose booleans/status only, never credentials.
- `GET /api/ops/metrics` — owner-IP-only operational snapshot with queue depth, active jobs, configured concurrency, process uptime, and informational scratch-disk availability. Structured Render logs also record queue wait, attempt duration, completed signing duration/result size, and stage/code for failures.
- `GET /api/v1/discord/health` — compatibility health endpoint for the Discord bot; returns `status: ok` only when zsign, Tigris configuration, and `JOB_ENCRYPTION_KEY` are present, otherwise HTTP 503 with `status: degraded`.
- `POST /sign` or `POST /api/v1/discord/sign` — submit a multipart signing request. By default the existing bot contract remains public and is rate-limited by source IP. Setting `API_CLIENTS_JSON` turns on per-bot `X-API-Key` authentication and per-client quotas; in that mode keys are required for submissions.
- `GET /api/jobs/:jobId?after=0` — poll a job. Authenticate with `Authorization: Bearer <jobToken>`.
- `POST /api/jobs/:jobId/download-url` — mint a signed download URL before the configured result-retention deadline; includes `expiresAt` (ISO-8601) and `expiresAtMs`.
- `POST /api/jobs/:jobId/ota-url` — mint a fresh iOS OTA link before the same deadline; includes `expiresAt` and `expiresAtMs`.
- `GET /ota/:jobId/:token/manifest.plist` — the iOS OTA manifest endpoint.

Everything else except `/doc` and `/doc/openapi.json` returns JSON 404. The only HTML is the owner-IP-restricted API reference page; there is no browser signer UI, certificate browsing, or CAPTCHA requirement for Discord bot API requests.

## `POST /sign` multipart contract

Use `Content-Type: multipart/form-data` (let `fetch`/`FormData` set its boundary). Supply the IPA as **one** of: `ipa` (file) or `ipaUrl` (public HTTPS URL). `ipaUrl` is the only URL-valued field; the certificate, provisioning profile, icon, and tweaks are files. The URL may be a signed/query-based download endpoint and does not need to end in `.ipa`; the server follows safe HTTPS redirects and assigns a `.ipa` filename when the path has no filename.

| Field | Type | Required | Notes |
|---|---|---:|---|
| `ipa` | file | One of `ipa` or `ipaUrl` | `.ipa`; 4 GiB default cap (`MAX_IPA_BYTES`) |
| `ipaUrl` | string | One of `ipa` or `ipaUrl` | Direct public HTTPS download URL; may use query parameters or redirects and need not end in `.ipa`; must be accessible from Render without private login/session |
| `p12` | file | yes | `.p12` or `.pfx`; alias `certificate` is supported for the supplied bot |
| `mobileprovision` | file | yes | `.mobileprovision`; alias `profile` is supported |
| `password` | text | no | Password for the P12; blank for unencrypted certificate |
| `appName` | text | no | Display name; alias `app_name` and `bundleName` are supported |
| `bundleId` | text | no | Bundle ID override; alias `bundle_id` is supported |
| `bundleVersion` | text | no | Version override; alias `version` is supported |
| `icon` | file | no | PNG app icon |
| `deb` | file | no | `.deb` package; extracts and injects compatible `.dylib` files |
| `dylib` | file | no | `.dylib` injected directly |
| `tweaks` | file(s) | no | Legacy bot alias, up to two files ending in `.deb` or `.dylib` |
| `injectExtensions` | text | no | Set `true` to inject tweaks into supported app extensions |
| `signer` | text | no | Only `zsign` is supported; omitted defaults to zsign. `rcodesign` is rejected explicitly, not silently ignored. |

### Discord bot compatibility

The API follows the provided Discord.js v14 bot's wire contract: accepts `certificate`, `profile`, `password`, `ipa` or `ipaUrl`, `appName`/`app_name`, `version`, `signer`, `icon`, and `tweaks`; returns a 202 JSON response with `success: true`, `jobId`, `jobToken`, `status`, `statusUrl`/`progressUrl`, and `poll_after_ms`; and later returns `status: completed` with `result.downloadUrl`, `result.otaUrl`, `result.ota_url`, and `result.installUrl`. Errors are JSON with an `error` string so the bot can display useful failures.

A short initial response example (identifiers are placeholders):

```json
{
  "success": true,
  "ok": true,
  "jobId": "<job-id>",
  "jobToken": "<job-token>",
  "status": "queued",
  "poll_after_ms": 1000,
  "statusUrl": "https://xsigner.onrender.com/api/jobs/<job-id>?after=0"
}
```

Poll with `Authorization: Bearer <jobToken>`. The server also supports the previous bot pattern that sends `Authorization: Bearer XSIGN_SECRET` on submission and reuses that bearer for the job it created, for backwards compatibility. New bot code should use the response's job-specific `jobToken` because it limits status/download access to that job.

The completion response's `result` object includes the signed IPA URL (temporary), an OTA install URL when the Bundle ID is available, app metadata, `signingTime`, and `resultExpiresAt` (ISO-8601) plus `resultExpiresAtMs`. The poll response also exposes those expiry fields at the top level for convenience. Keep the result deadline in your bot and warn users before the link expires. iOS install links use the `itms-services` scheme; a bot may wrap that with the OTA landing-page service if its setup requires one.

By default, submissions keep the existing no-key bot contract and are limited to 30 requests per source IP every 15 minutes (`API_SIGN_RATE_LIMIT`). To enable optional per-bot authentication, set `API_CLIENTS_JSON` in Render's environment settings. Once it contains one or more clients, **all signing submissions must send `X-API-Key`**; missing or invalid keys receive HTTP 401. Each client gets a separate quota (default 120 requests per 15 minutes), while authenticated traffic also has a shared per-IP safety ceiling (default 300 per 15 minutes). Status/results still require the job token. The existing `Authorization: Bearer ...` compatibility behavior is kept separate from `X-API-Key`.

Example `API_CLIENTS_JSON` value (replace both example keys with unique random secrets of at least 32 characters; do not commit real keys):

```json
{
  "discord-production": {"key": "REPLACE_WITH_A_UNIQUE_RANDOM_SECRET_OF_32_PLUS_CHARS", "limit": 120, "windowMs": 900000},
  "discord-staging": {"key": "USE_A_DIFFERENT_RANDOM_SECRET_OF_32_PLUS_CHARS", "limit": 20, "windowMs": 3600000}
}
```

Each object uses `key` (required), `limit` (optional positive integer), and `windowMs` (optional 60000–86400000 milliseconds). The top-level names are client IDs made of letters, digits, dots, underscores, or hyphens. Use a separate random key for every bot. The optional helper accepts `apiKey: process.env.XSIGNER_API_KEY` and adds the `X-API-Key` header only when provided. Leave `API_CLIENTS_JSON` unset until your bot is configured with the matching key. In standalone mode, quota counters are process-local; with `REDIS_URL` configured, per-client fixed-window quotas use atomic Redis counters and are shared across API instances.

### Node.js 22 / discord.js request pattern

`examples/discord-sign-api-client.js` exports a `submitAndPollXsign` helper. It uses Node 22's built-in `fetch`, `FormData`, and `Blob`, posts the file fields, polls the returned status URL with the job-specific token, calls the progress callback as status/stage changes, throws on failures, and returns the flattened completion response the bot expects (`data.otaUrl`, `data.downloadUrl`, etc.). For IPAs over 500 MiB, prefer `ipaUrl` when the source is a direct public link so the bot does not download and buffer the full IPA before forwarding it. The example helper caps attachment buffering at 500 MiB, matching the provided bot code pattern.

## Signing behavior

- The service's signing engine is zsign from `zhlynn/zsign`, built into the container image.
- Optional `.deb` inputs are extracted with `dpkg-deb`; `.dylib` files are passed to zsign for injection. An arbitrary `.deb` is not itself signed.
- Optional PNG icon, app name, Bundle ID, and version override are forwarded to zsign. When not supplied, the service attempts to read metadata from the IPA.
- Remote IPA downloads are streamed to a temporary file (not buffered whole in RAM), with a default cap of 4 GiB and a default timeout of 60 minutes. DNS results are checked against conservative IPv4/IPv6 non-public/special-use ranges and pinned to the actual HTTPS connection to mitigate DNS rebinding. Every redirect is independently re-resolved, checked and pinned. A 401/403 from the source host means that host denied the request; choose a direct publicly accessible download URL or meet the file host's documented requirements.
- **IPA storage tiering:** `LOCAL_IPA_THRESHOLD_BYTES=536870912` (512 MiB) is the default threshold. In the single-service deployment, uploaded IPA files at or below this size stay in Render-local temporary storage instead of being uploaded to Tigris. `ipaUrl` inputs are streamed to the local signing workspace; when their actual size is over the threshold and at or below the 4 GiB maximum, they are staged in Tigris for retry-safe handling. Uploaded IPAs above the threshold go to Tigris directly. Signed outputs at or below the threshold also stay in Render-local temporary storage; larger signed outputs go to Tigris. Shared Redis/BullMQ deployments use Tigris for uploaded files/results that must move between API and worker instances.
- The local tier uses files in Render's ephemeral `/tmp` filesystem, **not a 512 MiB in-memory Node.js Buffer**. That avoids risking out-of-memory crashes, but files in `/tmp` can disappear on restart/redeploy and are only intended for short-lived job data. zsign still requires local filesystem space to unpack and archive every IPA, including large Tigris-backed files.
- **Signing/archiving speed:** `ZSIGN_ZIP_LEVEL` defaults to `1` (faster archive creation than level `9` with modest compression). Set it to `0` for no compression and the fastest ZIP step, at the cost of a potentially larger IPA and a longer result upload; values `2`–`9` trade speed for size. If `MAX_CONCURRENT_JOBS` is unset, the service runs one signing job at a time to avoid CPU, memory, and scratch-disk contention. Raise concurrency only after measuring the worker.
- **Tigris transfer speed:** large S3 uploads use 16 MiB multipart parts with up to 4 part uploads in flight; up to 2 input objects are uploaded/downloaded concurrently, and known-size Tigris objects of 64 MiB or more are fetched using parallel byte-range reads (32 MiB ranges, up to 4 in flight). Transfer logs include elapsed time and average MiB/s. These defaults balance throughput with RAM and disk contention; if the instance is memory constrained, use `TIGRIS_UPLOAD_QUEUE_SIZE=2`, `TIGRIS_OBJECT_TRANSFER_CONCURRENCY=1`, or `TIGRIS_DOWNLOAD_CONCURRENCY=2`. Tune using actual Render logs rather than assuming higher concurrency is always faster. Large signed result download links point directly to Tigris; small local-tier result downloads stream through the API without loading the entire IPA into memory.
- Signed results, whether local or stored in Tigris, are deleted after the configured `SIGNED_IPA_TTL_MINUTES` window (default 10 minutes, safely clamped to 1–60). Completion and URL responses expose expiration timestamps; signed download/OTA URLs cannot outlive that deadline. Input objects and certificate material are deleted after success/failure.

## Error responses and request tracing

All JSON responses include the server-generated `X-Request-ID` response header; JSON bodies also include `requestId`. JSON errors follow `{ "success": false, "ok": false, "error": "...", "code": "...", "requestId": "..." }` while retaining endpoint-specific extra fields. Stable error codes include `API_KEY_REQUIRED`, `API_CLIENT_RATE_LIMITED`, `IP_RATE_LIMITED`, `AUTHENTICATED_IP_RATE_LIMITED`, `PAYLOAD_TOO_LARGE`, `NOT_FOUND`, `RESULT_EXPIRED`, `SERVICE_UNAVAILABLE` and `INTERNAL_ERROR`. When reporting a problem, include the request ID, not the job token or API key.

## Optional horizontal scaling with a shared queue

The default `render.yaml` keeps the current single-service in-process queue, so it does not require Redis and remains compatible with your working bot. To run several API instances and separate signing workers, provision a private Render Key Value (Redis-compatible) instance and set the same `REDIS_URL` on every API/worker. Set `MANIFEST_STORAGE=s3` on all of them so Tigris is the authoritative shared job-manifest store. The application then uses BullMQ for durable cross-instance queueing, worker locks/stalled-job recovery, and Redis-backed per-client quotas. Configure the public API with `RUN_SIGNING_WORKER=false`; configure each background worker with `RUN_SIGNING_WORKER=true` and `DATA_DIR=/tmp/xsigner-worker`. Workers run the same Docker image but do not expose an HTTP listener. Share the exact same `AWS_*`, `S3_BUCKET`, `JOB_ENCRYPTION_KEY`, `REDIS_URL`, retention, and signing settings across every instance. Never rotate `JOB_ENCRYPTION_KEY` without accounting for queued manifests encrypted by the old key.

See [`docs/SCALING.md`](docs/SCALING.md) before enabling this mode. It is opt-in and not activated merely by the default Blueprint; a separate Redis resource may incur additional Render charges. Do not enable horizontal scaling while job manifests still use local storage.

## Render and Tigris configuration

The included `render.yaml` defines the Docker service, zsign build, `/healthz` health-check, Tigris endpoint/bucket values, `JOB_ENCRYPTION_KEY`, owner-only docs IP, large-file limits, the 512 MiB local IPA threshold, and temporary work directory on `/data`. The persistent work disk provides capacity for zsign extraction and large files; small source/result IPA files use `/tmp`, while IPAs above the threshold use Tigris for staging/results. `/tmp` is ephemeral, not literal RAM, and does not survive a restart or redeploy.

Set these secrets in the Render dashboard only (never commit them):

```text
AWS_ACCESS_KEY_ID=<Tigris access key>
AWS_SECRET_ACCESS_KEY=<Tigris secret key>
```

Non-secret storage values: `LOCAL_IPA_THRESHOLD_BYTES=536870912` (512 MiB), `LOCAL_IPA_DIR=/tmp/xsigner-local-ipa`, and `LOCAL_RESULT_DIR=/tmp/xsigner-local-results`. Increase/decrease the threshold only after checking the Render instance memory and temporary-filesystem capacity; the threshold selects local storage, it does not buffer the entire IPA in RAM. Tigris values: `AWS_ENDPOINT_URL_S3=https://t3.storage.dev`, `AWS_ENDPOINT_URL_IAM=https://iam.storage.dev`, `AWS_REGION=auto`, `S3_BUCKET=xsigner`. Transfer knobs (with sensible defaults) are `PART_SIZE_BYTES=16777216`, `TIGRIS_UPLOAD_QUEUE_SIZE=4`, `TIGRIS_OBJECT_TRANSFER_CONCURRENCY=2`, `TIGRIS_PARALLEL_DOWNLOAD_THRESHOLD_BYTES=67108864`, `TIGRIS_DOWNLOAD_CHUNK_SIZE_BYTES=33554432`, and `TIGRIS_DOWNLOAD_CONCURRENCY=4`. `PART_SIZE_BYTES` must be at least 5 MiB for S3 multipart compatibility; queue/concurrency values are bounded by the application. Also keep `JOB_ENCRYPTION_KEY` set; it encrypts the certificate password while a job is queued. `PUBLIC_ORIGIN` should be `https://xsigner.onrender.com` or your API's public origin.

## Checks

```bash
npm install
npm run check
```

Checks validate the API-only surface, Discord.js field aliases and response contract, job polling/download/OTA route presence, remote IPA streaming, size limits, redirects, and JSON error behavior. A passing code check is not the same as a real live signing run; validate with a test IPA, P12, and profile on the deployed Render service.
