# xsigner — Render + Tigris + zsign

A Render-hosted iOS IPA signing website. The browser uploads directly to a **private Tigris bucket** using presigned multipart URLs. Render downloads files into a temporary workspace, runs the upstream [`zhlynn/zsign`](https://github.com/zhlynn/zsign) CLI, uploads the signed IPA, and issues a temporary download URL.

## Features

- **Direct large-file uploads:** multipart uploads go from the browser to Tigris; Render does not proxy the full IPA upload.
- **Signing:** the upstream zsign CLI runs in the Docker image built for Render.
- **Temporary downloads and OTA:** signed IPAs are delivered with expiring presigned URLs; an iOS OTA manifest is generated for supported devices and profiles.
- **CAPTCHA gate:** Google reCAPTCHA v2 is verified server-side on the job-creation request before signed upload URLs are issued. The secret is never sent to the browser.
- **Progress and logs:** browser uploads, worker downloads, zsign, archive creation, result uploads, and remote-URL downloads report progress in the signing console. The archiving phase shows an animated progress bar and periodic activity messages.
- **Credential handling:** Tigris credentials stay server-side in Render environment variables; they are not embedded into browser code or this ZIP.

## Architecture

- **Render web service:** website, API, queue, and compiled `zsign` executable.
- **Tigris (S3-compatible object storage):** private source files and signed IPAs. S3-compatible AWS SDK operations are used for multipart uploads, reads, deletes, and signed links.
- **Render persistent disk:** job metadata defaults to `/data/manifests` to avoid a storage read on every browser poll.
- **Temporary processing storage:** source files are downloaded into a temporary `/data/work` workspace only while signing, then removed after success or failure.

## Render deployment

The included `render.yaml` defines a Docker web service named **`xsigner`**, a `/health` check, a 40 GB persistent disk, Tigris environment values, and a generated `JOB_ENCRYPTION_KEY`.

1. Push this folder to your connected Git repository or deploy the project using your normal Render flow.
2. Create a **private Tigris bucket** named `xsigner` in the Tigris dashboard, or change `S3_BUCKET` in `render.yaml` to the exact bucket name you created.
3. In Tigris, create an access key scoped to that bucket with permission to create multipart uploads, upload parts, complete/abort multipart uploads, read objects, delete objects, and list objects if you enable remote manifest recovery. Use the narrowest permission set that supports the app.
4. Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in Render's environment settings. `render.yaml` deliberately leaves both as unsynced secret values. Do not put the real values in Git, the ZIP, `README.md`, or `public/index.html`.
5. Set `RECAPTCHA_SECRET_KEY` in Render, and make sure `RECAPTCHA_ALLOWED_HOSTNAMES` matches the deployed hostname (by default `xsigner.onrender.com`). Render generates `JOB_ENCRYPTION_KEY` from the blueprint.
6. Deploy and wait for the service to become **Live**. Check `/health`; it should report `signer: "zsign"`, `signerPresent: true`, storage configured, encryption configured, and `recaptchaConfigured: true`.
7. Configure CORS on the Tigris bucket using `tigris-cors.json` (see below), then test a small upload and a complete signing job.

### Tigris environment values

The Render blueprint sets these non-secret values:

```text
AWS_ENDPOINT_URL_S3=https://t3.storage.dev
AWS_ENDPOINT_URL_IAM=https://iam.storage.dev
AWS_REGION=auto
S3_BUCKET=xsigner
```

Set the following secrets **in the Render dashboard only**:

```text
AWS_ACCESS_KEY_ID=<Tigris access key beginning with tid_>
AWS_SECRET_ACCESS_KEY=<Tigris secret key beginning with tsec_>
```

`AWS_ENDPOINT_URL_IAM` is included because it is part of your Tigris setup, but this application uses only the S3-compatible endpoint. The code uses virtual-host-style bucket URLs with Tigris's global S3 endpoint so presigned URLs are signed for the proper host.

The app can start so `/health` is available even before storage credentials are configured, but uploads/signing will return a configuration error until `S3_BUCKET`, both AWS credentials, and the endpoint/region are available.

## CORS

Apply the rules from `tigris-cors.json` to your Tigris bucket. They allow direct browser requests from `https://xsigner.onrender.com` and expose `ETag`, which the browser needs to complete multipart uploads. Update `AllowedOrigins` to the exact HTTPS origin if you use a custom domain. For local development, add your localhost origin only while testing and remove it before production.

If uploads return a browser CORS error, or the client reports that the response did not expose `ETag`, check the Tigris bucket's CORS settings first. The bucket can remain private; do not make it public to enable direct upload.

## Lifecycle and retention

Where supported by your Tigris bucket settings, configure incomplete multipart uploads to be aborted after a day. The service removes uploaded source IPA, P12, provisioning-profile, icon, and tweak objects after signing finishes or fails. **Signed IPA result objects are explicitly deleted from Tigris 10 minutes after signing completes** by an application-side sweep (10-second default sweep interval); download and OTA URLs are limited to the remaining retention window. Job manifests are retained separately according to `JOB_TTL_HOURS` (24 hours by default). If the service is suspended, the sweep resumes on the next startup/wakeup; deleted objects can still be subject to any bucket retention/soft-delete settings you enabled.

## Environment variables

| Variable | Required | Default / notes |
|---|---:|---|
| `AWS_ENDPOINT_URL_S3` | Yes | `https://t3.storage.dev` |
| `AWS_ENDPOINT_URL_IAM` | No for this app | `https://iam.storage.dev`; not used by the S3 client |
| `AWS_REGION` | Yes | `auto` |
| `S3_BUCKET` | Yes | `xsigner`; must exactly match your Tigris bucket |
| `AWS_ACCESS_KEY_ID` | Yes | Secret; set in Render only |
| `AWS_SECRET_ACCESS_KEY` | Yes | Secret; set in Render only |
| `JOB_ENCRYPTION_KEY` | Yes | Generated by Render; encrypts a queued P12 password |
| `ZSIGN_BIN` | No | `/usr/local/bin/zsign` |
| `PUBLIC_ORIGIN` | Recommended | `https://xsigner.onrender.com`; base URL used in OTA manifests |
| `OWNER_IP` | No | Owner IPv4 allowed to view the Discord API documentation page; default is `168.91.23.165`. On Render, owner detection uses Cloudflare's overwritten `CF-Connecting-IP` header and fails closed if it is missing/invalid. Does not restrict `/sign`. `XSIGNER_OWNER_IP` remains a backward-compatible fallback. |
| `RECAPTCHA_SECRET_KEY` | Yes | Google reCAPTCHA secret; set in Render only |
| `RECAPTCHA_ALLOWED_HOSTNAMES` | Recommended | Comma-separated allowed hostnames |
| `MAX_IPA_BYTES` | No | `4294967296` (4 GiB) |
| `PART_SIZE_BYTES` | No | `67108864` (64 MiB) |
| `DATA_DIR` | No | `/data` in Render |
| `MAX_CONCURRENT_JOBS` | No | `1` initially, to limit disk/RAM pressure |
| `JOB_TTL_HOURS` | No | `24` |
| `UPLOAD_TTL_HOURS` | No | `6` |
| `SIGN_TIMEOUT_MS` | No | `2700000` (45 minutes) |
| `MANIFEST_STORAGE` | No | `local` by default; set to `s3` to also store manifests in Tigris |
| `S3_RECOVER_ON_START` | No | `false`; when `true` with `MANIFEST_STORAGE=s3`, startup scans remote manifests and may issue many list/read requests |
| `S3_MAINTENANCE_INTERVAL_MS` | No | Render blueprint sets `3600000` (hourly interrupted-job recovery/older job cleanup) |
| `SIGNED_IPA_TTL_MINUTES` | No | `10`; signed IPA objects are deleted after this retention period (minimum 1 minute) |
| `SIGNED_IPA_CLEANUP_INTERVAL_MS` | No | `10000`; interval for the signed-result expiry sweep |
| `REMOTE_FETCH_TIMEOUT_MS` | No | 20 minutes for public HTTPS URL source downloads |

## API overview

- `GET /health` — service, zsign executable, object-storage and encryption readiness.
- `GET /api/config` — public upload-size configuration.
- `POST /api/jobs` — validates the single-use reCAPTCHA token and creates a job and multipart uploads; returns a one-time job token.
- `POST /api/jobs/:id/part-urls` — mint short-lived multipart upload URLs.
- `POST /api/jobs/:id/complete-upload` — complete the multipart upload.
- `POST /api/jobs/:id/sign` — queue signing with optional password and metadata overrides.
- `GET /api/jobs/:id?after=<log-id>` — authenticated job status plus new console lines.
- `POST /api/jobs/:id/download-url` — request an S3-presigned download URL that expires no later than the signed IPA 10-minute retention deadline.
- `POST /api/jobs/:id/ota-url` and `GET /ota/:id/:token/manifest.plist` — create and serve a temporary iOS OTA installation manifest.
- `POST /sign` (also `/api/v1/discord/sign`) — public, rate-limited Discord bot API using `multipart/form-data`. Supply `ipa` as a file or the optional `ipaUrl` as the only URL field; `p12` and `mobileprovision` are file uploads. For compatibility with the provided Discord bot pattern, `certificate`/`profile` and a `tweaks` file (`.deb` or `.dylib`) are accepted aliases too. Optional files include `icon` (PNG), `deb`, and `dylib`; metadata text fields include `appName`, `bundleId`, `bundleVersion`, `password`, and `injectExtensions`. No API key or owner-IP restriction is required for `/sign`.
- `GET /api/owner/discord-api-docs` — Discord API documentation JSON, accessible only from the configured owner IP. The website hides the API docs navigation item from other IPs; this does not lock the public `/sign` endpoint.
- `GET /api/free-certificates/list/:status[/amount]` and `/api/free-certificates/download/...` — NexCerts proxy endpoints.
- `POST /api/certchecker/checkCert` — same-origin P12/mobileprovision checker proxy.

The response includes a unique `jobToken`; use it as `Authorization: Bearer <jobToken>` when polling status or requesting download/OTA URLs. For compatibility with the provided Discord bot's `Authorization: Bearer XSIGN_SECRET` poller, if a caller supplies a bearer on its initial POST the API hashes that value against that job only and also accepts it for that job's poll/download/OTA endpoints. Submission is still public and no API key is required. New clients should prefer `jobToken`. Completed API-job status responses include a `result` object with `otaUrl`/`installUrl`, a short-lived `downloadUrl`, app metadata, and signing time so the bot can return install/download responses without needing a second conversion step. The `/api/v1/discord/health` alias is available for bot status checks. The browser keeps its job token in page memory, never in the download URL. Passwords are encrypted in the private manifest while queued, redacted from captured output, and cleared from manifests after signing succeeds or fails.

## Security notes

- Keep the Tigris bucket private and store credentials only in Render environment variables.
- `/health` reports configuration readiness but does not prove the app can perform a real storage read/write. Validate with a test upload and signing run.
- Do not rotate `JOB_ENCRYPTION_KEY` while jobs are queued, because queued P12 passwords are encrypted with it.
- Anonymous uploads/signing can consume CPU and storage. Keep IP rate limits enabled, start with `MAX_CONCURRENT_JOBS=1`, and consider an access gate or quota before public launch.
- Job manifests use the Render persistent disk by default (`MANIFEST_STORAGE=local`). In this mode, jobs depend on the persistent disk remaining attached to this single service instance. Set `MANIFEST_STORAGE=s3` only if you explicitly want remote manifests.
- `S3_RECOVER_ON_START=true` can list/read historical manifest objects. Leave it off unless you deliberately want remote manifest recovery.
- reCAPTCHA tokens are single-use and expire quickly; the site submits the token with the job-creation request and verifies it on the server immediately before it returns multipart upload URLs. This avoids storing a fragile in-memory preflight pass and does not require the token to remain valid throughout a long file upload.
- zsign supports `.dylib` injection and PNG icon replacement, but cannot sign a Debian `.deb` package directly. The site extracts `.dylib` files from a `.deb`; tweak compatibility is not guaranteed.
- An OTA manifest does not bypass Apple's signing, provisioning, trust, or device-eligibility requirements.

## Migration notes

Changing the endpoint does **not** copy existing Backblaze objects into Tigris. New uploads will use Tigris after deployment; old queued jobs or output links that point to Backblaze objects may stop working if those objects have not been copied. Let active signing jobs finish before switching, and migrate any objects you need to retain separately. Signed IPA objects are independently deleted after 10 minutes. Remaining job metadata is retained for troubleshooting until the job TTL cleanup removes it.

## Local checks

```bash
npm install
npm run check
npm start
```

The Docker build needs network access to clone the pinned upstream zsign release.

## Upstream and documentation

- Tigris documentation: https://www.tigrisdata.com/docs/
- Tigris S3-compatible storage and endpoint overview: https://www.tigrisdata.com/features/
- zsign source and usage: https://github.com/zhlynn/zsign
- Google reCAPTCHA display: https://developers.google.com/recaptcha/docs/display
- Google reCAPTCHA verification: https://developers.google.com/recaptcha/docs/verify
- NexCerts API: https://sideloading.net
- pinned zsign v1.1.2 release: https://github.com/zhlynn/zsign/tree/v1.1.2
- zsign license: https://github.com/zhlynn/zsign/blob/v1.1.2/LICENSE
