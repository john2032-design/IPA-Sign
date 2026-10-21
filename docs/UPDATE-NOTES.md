# xsigner API hardening update

This source package includes the selected API recommendations while preserving the existing Discord.js submission and polling contract.

## Included

1. **Progress redaction fix:** application-generated status messages are not scrubbed with the certificate password. Raw signer output and failure details use dedicated secret sanitization; output does not insert `[REDACTED]` placeholders.
2. **Optional bot authentication and quotas:** set `API_CLIENTS_JSON` to require `X-API-Key` and configure per-client limits. Leaving it unset preserves the current working bot's public submission contract. With `REDIS_URL`, per-client quotas use atomic Redis counters across API instances.
5. **Remote URL SSRF mitigation:** remote HTTPS downloads validate public/global IP ranges, pin resolved DNS answers to the outbound connection, and re-resolve each redirect.
7. **Operational visibility:** `/healthz/dependencies`, owner-only `/api/ops/metrics`, request-correlated structured logs, queue depths, job queue-wait/signing durations, result size, failure phase/code, and scratch-disk availability. Disk readings are informational only.
8. **Consistent errors and tests:** stable JSON error codes, request IDs, updated OpenAPI response headers, and regression/mocked integration tests.
9. **Configurable result retention:** `SIGNED_IPA_TTL_MINUTES` safely clamps to 1–60 minutes; response payloads expose precise expiry timestamps and URLs cannot outlive the result deletion deadline.
10. **Optional scale-out architecture:** set up Redis/BullMQ and S3-backed manifests for separate API and signing-worker services. It is not enabled by default and no additional billable resources are created automatically. See [`SCALING.md`](SCALING.md).

## Explicitly not included

- No extra disk capacity admission checks, upload concurrency quotas, or `.deb` extraction-size limits were added.
- No idempotency key or cancellation endpoint was added.
- The P12 password is still passed to zsign by its supported command-line interface; changing that transport was outside this update.

## Validation boundary

`npm run check` validates syntax, the API contract, remote-download security using mocks, Discord client compatibility, documentation/owner-IP rules, secret logging, diagnostics, retention, and scale-out configuration. These tests do not replace a real Render deployment, real Tigris/Redis connectivity test, or a live end-to-end signing run.
