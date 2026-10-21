const DEFAULT_API_BASE = 'https://xsigner.onrender.com';
const MAX_SMALL_FILE_BYTES = 16 * 1024 * 1024;
const MAX_DISCORD_IPA_ATTACHMENT_BYTES = 500 * 1024 * 1024;
const MAX_TWEAK_FILE_BYTES = 256 * 1024 * 1024;

async function attachmentToBlob(attachment, maxBytes, label) {
  if (!attachment?.url) throw new Error(`${label} attachment is missing a download URL.`);
  const response = await fetch(attachment.url, {signal: AbortSignal.timeout(60_000)});
  if (!response.ok) throw new Error(`Could not download ${label} attachment (HTTP ${response.status}).`);
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > maxBytes) throw new Error(`${label} attachment exceeds the ${maxBytes}-byte client limit.`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength < 1) throw new Error(`${label} attachment is empty.`);
  if (bytes.byteLength > maxBytes) throw new Error(`${label} attachment exceeds the ${maxBytes}-byte client limit.`);
  return new Blob([bytes], {type: attachment.contentType || 'application/octet-stream'});
}

/**
 * Submit a Discord.js interaction's signing inputs to xsigner and poll until done.
 * For IPA files over 500 MiB, use ipaUrl to avoid buffering the IPA in the bot process.
 * @param {object} input
 * @param {string} [input.apiBase]
 * @param {string} [input.apiKey] Optional API key. Required only if the service owner enables API_CLIENTS_JSON.
 * @param {object} [input.ipa] Discord.js Attachment object for an uploaded .ipa (up to 500 MiB in this helper)
 * @param {string} [input.ipaUrl] public direct HTTPS .ipa URL (mutually exclusive with ipa)
 * @param {object} input.certificate Discord.js Attachment (.p12/.pfx)
 * @param {object} input.profile Discord.js Attachment (.mobileprovision)
 * @param {string} [input.password]
 * @param {string} [input.appName]
 * @param {string} [input.bundleId]
 * @param {string} [input.version]
 * @param {object} [input.icon] optional PNG Discord.js Attachment
 * @param {object} [input.deb] optional .deb Discord.js Attachment
 * @param {object} [input.dylib] optional .dylib Discord.js Attachment
 * @param {object[]} [input.tweaks] optional legacy .deb/.dylib attachment array
 * @param {boolean} [input.injectExtensions]
 * @param {number} [input.maxWaitMs] total polling deadline, defaults to 15 minutes
 * @param {(status: object) => void|Promise<void>} [input.onProgress]
 * @returns {Promise<object>} flattened completion response expected by the provided bot code
 */
export async function submitAndPollXsign(input) {
  const apiBase = String(input.apiBase || DEFAULT_API_BASE).trim().replace(/\/+$/, '')
    .replace(/\/api\/v1\/discord\/(?:sign|custom-sign)\/?$/i, '');
  if (Boolean(input.ipa) === Boolean(input.ipaUrl)) {
    throw new Error('Provide exactly one source: an IPA attachment or ipaUrl.');
  }
  if (!input.certificate?.url || !String(input.certificate.name || '').toLowerCase().match(/\.(p12|pfx)$/)) {
    throw new Error('A .p12 or .pfx certificate attachment is required.');
  }
  if (!input.profile?.url || !String(input.profile.name || '').toLowerCase().endsWith('.mobileprovision')) {
    throw new Error('A .mobileprovision attachment is required.');
  }

  const form = new FormData();
  if (input.ipaUrl) {
    form.append('ipaUrl', input.ipaUrl);
  } else {
    const ipaBlob = await attachmentToBlob(input.ipa, MAX_DISCORD_IPA_ATTACHMENT_BYTES, 'IPA');
    form.append('ipa', ipaBlob, input.ipa.name || 'app.ipa');
  }
  form.append('certificate', await attachmentToBlob(input.certificate, MAX_SMALL_FILE_BYTES, 'P12'), input.certificate.name);
  form.append('profile', await attachmentToBlob(input.profile, MAX_SMALL_FILE_BYTES, 'mobileprovision'), input.profile.name);
  form.append('password', String(input.password || ''));
  if (input.appName) form.append('appName', input.appName);
  if (input.bundleId) form.append('bundleId', input.bundleId);
  if (input.version) form.append('version', input.version);
  if (input.injectExtensions) form.append('injectExtensions', 'true');
  if (input.icon) form.append('icon', await attachmentToBlob(input.icon, MAX_SMALL_FILE_BYTES, 'Icon'), input.icon.name || 'icon.png');
  if (input.deb) form.append('deb', await attachmentToBlob(input.deb, MAX_TWEAK_FILE_BYTES, 'DEB'), input.deb.name || 'tweak.deb');
  if (input.dylib) form.append('dylib', await attachmentToBlob(input.dylib, 128 * 1024 * 1024, 'Dylib'), input.dylib.name || 'tweak.dylib');
  for (const [i, tweak] of (input.tweaks || []).entries()) {
    const name = String(tweak.name || '').toLowerCase();
    if (name.endsWith('.deb')) form.append('tweaks', await attachmentToBlob(tweak, MAX_TWEAK_FILE_BYTES, 'Tweak'), tweak.name);
    else if (name.endsWith('.dylib')) form.append('tweaks', await attachmentToBlob(tweak, 128 * 1024 * 1024, 'Tweak'), tweak.name);
    else throw new Error(`Tweak ${i + 1} must be a .deb or .dylib file.`);
  }

  const submitHeaders = input.apiKey ? {'X-API-Key': String(input.apiKey)} : {};
  const submit = await fetch(`${apiBase}/api/v1/discord/sign`, {
    method: 'POST', headers: submitHeaders, body: form, signal: AbortSignal.timeout(60 * 60 * 1000)
  });
  const initial = await submit.json().catch(() => ({}));
  if (submit.status !== 202 || initial.success !== true) {
    throw new Error(initial.error || initial.message || `Signing API submission failed (HTTP ${submit.status}).`);
  }
  if (!initial.statusUrl || !initial.jobToken || !initial.jobId) {
    throw new Error('Signing API returned an incomplete job response (missing statusUrl, jobToken, or jobId).');
  }

  const maxWaitMs = Math.max(60_000, Number(input.maxWaitMs || 15 * 60 * 1000));
  const deadline = Date.now() + maxWaitMs;
  let lastKey = '';
  while (Date.now() < deadline) {
    const remainingMs = deadline - Date.now();
    const pause = Math.min(Math.max(250, Number(initial.poll_after_ms || 1000)), remainingMs);
    await new Promise(resolve => setTimeout(resolve, pause));
    const pollUrl = new URL(initial.statusUrl);
    const response = await fetch(pollUrl, {
      headers: {Authorization: `Bearer ${initial.jobToken}`},
      signal: AbortSignal.timeout(20_000)
    });
    const status = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(status.error || `Status polling failed (HTTP ${response.status}).`);
    const key = `${status.status}:${status.progress}:${status.stage}:${status.message}`;
    if (key !== lastKey) {
      lastKey = key;
      if (typeof input.onProgress === 'function') await input.onProgress(status);
    }
    if (status.status === 'failed') throw new Error(status.error || status.message || 'Signing job failed.');
    if (status.status === 'completed') {
      const result = status.result || {};
      if (!result.downloadUrl) throw new Error(result.error || 'Signing completed, but the temporary download URL is unavailable.');
      return {...status, ...result, data: {...status, ...result}, jobId: initial.jobId};
    }
  }
  throw new Error(`Signing job ${initial.jobId} did not finish within ${Math.round(maxWaitMs / 60000)} minutes. The job may still be running; poll ${initial.statusUrl} with its jobToken.`);
}

export function wrapOtaInstallUrl(otaUrl, otaBaseUrl = 'https://xsign-install.onrender.com') {
  if (typeof otaUrl !== 'string' || !/^itms-services:\/\//i.test(otaUrl)) return otaUrl;
  return `${String(otaBaseUrl).replace(/\/+$/, '')}/install.html?ota=${encodeURIComponent(otaUrl)}`;
}
