# xsigner — API-only IPA signing service

This project runs an API-only Node.js service on Render. It does not serve a website UI. `POST /sign` (also available as `POST /api/v1/discord/sign`) queues IPA signing through the upstream zsign CLI, stores source/result objects in a private Tigris S3-compatible bucket, and returns temporary download and OTA-install links.

## Endpoints

- `GET /` — JSON service and endpoint summary (not HTML).
- `GET /doc` — owner-IP-restricted HTML documentation page; `GET /doc/openapi.json` serves the equivalent OpenAPI JSON. Both use `OWNER_IP` (fallback `XSIGNER_OWNER_IP`, then `168.91.23.165`). The `/sign` API itself remains public and has no owner-IP restriction.
- `GET /healthz` — Render runtime readiness probe; returns HTTP 200 only when zsign, Tigris configuration, and job encryption are available, otherwise HTTP 503. The Render service health check is configured to `/healthz`.
- `GET /health` — backwards-compatible alias of `/healthz`.
- `GET /api/v1/discord/health` — compatibility health endpoint for the Discord bot; returns `status: ok` only when zsign, Tigris configuration, and `JOB_ENCRYPTION_KEY` are present, otherwise HTTP 503 with `status: degraded`.
- `POST /sign` or `POST /api/v1/discord/sign` — submit a multipart signing request; public, no API key and no owner-IP restriction, with per-source-IP rate limiting.
- `GET /api/jobs/:jobId?after=0` — poll a job. Authenticate with `Authorization: Bearer <jobToken>`.
- `POST /api/jobs/:jobId/download-url` — mint a signed download URL before the 10-minute result-retention deadline.
- `POST /api/jobs/:jobId/ota-url` — mint a fresh iOS OTA link before the same deadline.
- `GET /ota/:jobId/:token/manifest.plist` — the iOS OTA manifest endpoint.

Everything else except `/doc` and `/doc/openapi.json` returns JSON 404. The only HTML is the owner-IP-restricted API reference page; there is no browser signer UI, certificate browsing, or CAPTCHA requirement for Discord bot API requests.

## `POST /sign` multipart contract

Use `Content-Type: multipart/form-data` (let `fetch`/`FormData` set its boundary). Supply the IPA as **one** of: `ipa` (file) or `ipaUrl` (public HTTPS URL). `ipaUrl` is the only URL-valued field; the certificate, provisioning profile, icon, and tweaks are files.

| Field | Type | Required | Notes |
|---|---|---:|---|
| `ipa` | file | One of `ipa` or `ipaUrl` | `.ipa`; 4 GiB default cap (`MAX_IPA_BYTES`) |
| `ipaUrl` | string | One of `ipa` or `ipaUrl` | Direct public HTTPS URL accessible from Render without private login/session |
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

The completion response's `result` object includes the signed IPA URL (temporary), an OTA install URL when the Bundle ID is available, app metadata, and `signingTime`. iOS install links use the `itms-services` scheme; a bot may wrap that with the OTA landing-page service if its setup requires one.

The built-in per-IP limit defaults to 30 submissions every 15 minutes (`API_SIGN_RATE_LIMIT`). Requests from a Discord bot deployment all share the bot host's egress IP, so tune this setting according to usage while preserving abuse protection. Submission does not require an API key or match the owner's IP. Status/result routes require a job token.

### Node.js 22 / discord.js request pattern

`examples/discord-sign-api-client.js` exports a `submitAndPollXsign` helper. It uses Node 22's built-in `fetch`, `FormData`, and `Blob`, posts the file fields, polls the returned status URL with the job-specific token, calls the progress callback as status/stage changes, throws on failures, and returns the flattened completion response the bot expects (`data.otaUrl`, `data.downloadUrl`, etc.). For IPAs over 500 MiB, prefer `ipaUrl` when the source is a direct public link so the bot does not download and buffer the full IPA before forwarding it. The example helper caps attachment buffering at 500 MiB, matching the provided bot code pattern.

## Signing behavior

- The service's signing engine is zsign from `zhlynn/zsign`, built into the container image.
- Optional `.deb` inputs are extracted with `dpkg-deb`; `.dylib` files are passed to zsign for injection. An arbitrary `.deb` is not itself signed.
- Optional PNG icon, app name, Bundle ID, and version override are forwarded to zsign. When not supplied, the service attempts to read metadata from the IPA.
- Remote IPA downloads are streamed to a temporary file (not buffered whole in RAM), default cap 4 GiB and default timeout 60 minutes. A 401/403 from the source host means that host denied the request; choose a direct publicly accessible download URL or meet the file host's documented requirements. Each redirect is revalidated as public HTTPS to prevent SSRF through a redirect target.
- Signing needs temporary local filesystem space for zsign's extraction, modifications, archive, and output. Tigris stores uploaded inputs and completed output, but does not substitute for the working directory required by zsign.
- Signed IPA result objects are deleted from Tigris 10 minutes after completion (`SIGNED_IPA_TTL_MINUTES=10`). Signed download/OTA URLs expire no later than that deadline. Input objects and certificate material are deleted after success/failure.

## Render and Tigris configuration

The included `render.yaml` defines the Docker service, zsign build, `/healthz` health-check, Tigris endpoint/bucket values, `JOB_ENCRYPTION_KEY`, owner-only docs IP, large-file limits, and temporary work directory on `/data`. The Render Blueprint includes the persistent work disk because large signing jobs require extraction/temporary workspace capacity; Tigris is the durable object layer for uploaded files and signed results.

Set these secrets in the Render dashboard only (never commit them):

```text
AWS_ACCESS_KEY_ID=<Tigris access key>
AWS_SECRET_ACCESS_KEY=<Tigris secret key>
```

Non-secret Tigris values: `AWS_ENDPOINT_URL_S3=https://t3.storage.dev`, `AWS_ENDPOINT_URL_IAM=https://iam.storage.dev`, `AWS_REGION=auto`, `S3_BUCKET=xsigner`. Also keep `JOB_ENCRYPTION_KEY` set; it encrypts the certificate password while a job is queued. `PUBLIC_ORIGIN` should be `https://xsigner.onrender.com` or your API's public origin.

## Checks

```bash
npm install
npm run check
```

Checks validate the API-only surface, Discord.js field aliases and response contract, job polling/download/OTA route presence, remote IPA streaming, size limits, redirects, and JSON error behavior. A passing code check is not the same as a real live signing run; validate with a test IPA, P12, and profile on the deployed Render service.
