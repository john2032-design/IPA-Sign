import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import net from 'node:net';

const source = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const start = source.indexOf('function normalizeIp(value) {');
const end = source.indexOf('function storageConfigured() {', start);
assert(start >= 0 && end > start, 'owner IP helper block must exist');
const helpers = source.slice(start, end);
const context = {
  net,
  process: {env: {NODE_ENV: 'production', OWNER_IP: '168.91.23.165'}},
  Buffer,
  result: null
};
vm.createContext(context);
vm.runInContext(`${helpers}\nglobalThis.ownerGate = isOwnerRequest; globalThis.ipNormalize = normalizeIp;`, context);
const req = (headers = {}, socket = {}, ip = '') => ({headers, socket, ip});
assert.equal(context.ipNormalize('168.91.23.165'), '168.91.23.165');
assert.equal(context.ipNormalize('::ffff:168.91.23.165'), '168.91.23.165');
assert.equal(context.ownerGate(req({'cf-connecting-ip': '168.91.23.165', 'x-forwarded-for': '9.9.9.9'})), true);
assert.equal(context.ownerGate(req({'cf-connecting-ip': '::ffff:168.91.23.165'})), true);
assert.equal(context.ownerGate(req({'cf-connecting-ip': '8.8.8.8'})), false);
assert.equal(context.ownerGate(req({'x-forwarded-for': '168.91.23.165'}, {remoteAddress: '168.91.23.165'}, '168.91.23.165')), false, 'production must fail closed if trusted CF header is absent');
context.process.env.NODE_ENV = 'development';
assert.equal(context.ownerGate(req({}, {remoteAddress: '::ffff:168.91.23.165'})), true, 'development can use socket fallback');
console.log('Owner-only documentation IP gate passed: exact IP/mapped IPv4 accepted, other IP/spoofed X-Forwarded-For rejected, production missing trusted header fails closed.');
