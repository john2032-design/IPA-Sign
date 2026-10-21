import assert from 'node:assert/strict';
import {submitAndPollXsign, wrapOtaInstallUrl} from '../examples/discord-sign-api-client.js';

const originalFetch = globalThis.fetch;
const calls = [];
let uploadedForm = null;
let expectedApiKey = null;
let progressCalls = 0;
globalThis.fetch = async (urlValue, options = {}) => {
  const url = String(urlValue);
  calls.push({url, options});
  if (url.startsWith('https://discord-files.example/')) {
    return new Response(new Uint8Array([1, 2, 3, 4]), {status: 200, headers: {'content-length': '4', 'content-type': 'application/octet-stream'}});
  }
  if (url === 'https://api.example/api/v1/discord/sign') {
    assert.equal(options.method, 'POST');
    if (expectedApiKey) assert.equal(options.headers?.['X-API-Key'], expectedApiKey, 'configured bot key must be sent on submission');
    else assert.equal(options.headers?.['X-API-Key'], undefined, 'legacy default request must omit the API-key header');
    assert.ok(options.body instanceof FormData, 'Discord client must submit FormData');
    uploadedForm = options.body;
    assert.equal(uploadedForm.get('ipaUrl'), 'https://cdn.example/app.ipa');
    assert.equal(uploadedForm.get('ipa'), null, 'when ipaUrl is used the IPA file field must be absent');
    assert.ok(uploadedForm.get('certificate') instanceof Blob, 'certificate must be uploaded as a file');
    assert.ok(uploadedForm.get('profile') instanceof Blob, 'mobileprovision must be uploaded as a file');
    assert.equal(uploadedForm.get('appName'), 'Example App');
    assert.equal(uploadedForm.get('bundleId'), 'com.example.app');
    assert.equal(uploadedForm.get('version'), '1.2.3');
    return new Response(JSON.stringify({
      success: true, ok: true, status: 'queued', jobId: 'fake-job-id', jobToken: 'job-token',
      statusUrl: 'https://api.example/api/jobs/fake-job-id?after=0', poll_after_ms: 1
    }), {status: 202, headers: {'content-type': 'application/json'}});
  }
  if (url === 'https://api.example/api/jobs/fake-job-id?after=0') {
    assert.equal(options.headers.Authorization, 'Bearer job-token');
    return new Response(JSON.stringify({
      success: true, ok: true, status: 'completed', progress: 100, stage: 'completed',
      result: {
        appName: 'Example App', bundleId: 'com.example.app', version: '1.2.3',
        downloadUrl: 'https://download.example/signed.ipa',
        otaUrl: 'itms-services://?action=download-manifest&url=https%3A%2F%2Fapi.example%2Fmanifest.plist',
        installUrl: 'itms-services://?action=download-manifest&url=https%3A%2F%2Fapi.example%2Fmanifest.plist',
        signingTime: '12s'
      }
    }), {status: 200, headers: {'content-type': 'application/json'}});
  }
  throw new Error(`Unexpected mock request ${url}`);
};

try {
  const result = await submitAndPollXsign({
    apiBase: 'https://api.example',
    ipaUrl: 'https://cdn.example/app.ipa',
    certificate: {url: 'https://discord-files.example/cert', name: 'cert.p12'},
    profile: {url: 'https://discord-files.example/profile', name: 'profile.mobileprovision'},
    password: 'example-password', appName: 'Example App', bundleId: 'com.example.app', version: '1.2.3',
    onProgress: status => { assert.equal(status.status, 'completed'); progressCalls++; }
  });
  assert.ok(uploadedForm);
  assert.equal(result.jobId, 'fake-job-id');
  assert.equal(result.downloadUrl, 'https://download.example/signed.ipa');
  assert.equal(result.otaUrl.startsWith('itms-services://'), true);
  assert.equal(result.data.downloadUrl, result.downloadUrl);
  assert.equal(progressCalls, 1);
  assert.equal(wrapOtaInstallUrl(result.otaUrl, 'https://install.example').startsWith('https://install.example/install.html?ota='), true);
  assert.equal(calls.length, 4, 'two attachment downloads, one submit, and one poll are expected');

  expectedApiKey = 'mock-only-api-key-that-is-long-enough-for-a-test-123';
  await submitAndPollXsign({
    apiBase: 'https://api.example', ipaUrl: 'https://cdn.example/app.ipa',
    certificate: {url: 'https://discord-files.example/cert', name: 'cert.p12'},
    profile: {url: 'https://discord-files.example/profile', name: 'profile.mobileprovision'},
    password: 'example-password', appName: 'Example App', bundleId: 'com.example.app', version: '1.2.3', apiKey: expectedApiKey
  });
  const secondSubmit = calls.slice(4).find(call => call.url === 'https://api.example/api/v1/discord/sign');
  assert.equal(secondSubmit.options.headers['X-API-Key'], expectedApiKey, 'optional API key should be attached only to submission');
  console.log('Discord client mock integration passed: legacy no-key mode, optional X-API-Key mode, multipart aliases, job-token polling, progress, download, and OTA result.');
} finally {
  globalThis.fetch = originalFetch;
}
