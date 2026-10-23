import assert from 'node:assert/strict';
import fs from 'node:fs';

const server = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const docker = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
const render = fs.readFileSync(new URL('../render.yaml', import.meta.url), 'utf8');
const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const scaling = fs.readFileSync(new URL('../docs/SCALING.md', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');

assert(server.includes('const ZSIGN_ZIP_LEVEL_CONFIG = Number(process.env.ZSIGN_ZIP_LEVEL ?? 1);'), 'zsign compression must default to a fast configurable level');
assert(server.includes('ZSIGN_ZIP_LEVEL_CONFIG >= 0 && ZSIGN_ZIP_LEVEL_CONFIG <= 9'), 'zsign compression must be bounded to levels 0–9');
assert(server.includes("'-z', String(ZSIGN_ZIP_LEVEL)"), 'configured compression level must be passed to zsign');
assert(!server.includes("'-z', '9'"), 'zsign must not hard-code slow maximum compression');
assert(server.includes('Number(process.env.MAX_CONCURRENT_JOBS ?? 1)'), 'unconfigured signing concurrency must default to one job');
assert(docker.includes('make VERSION=${ZSIGN_VERSION} -j"$(nproc)"'), 'zsign Docker build should use all available build CPUs');
assert(docker.includes('ENV ZSIGN_ZIP_LEVEL=1'), 'container default should use fast compression');
assert(render.includes('      - key: ZSIGN_ZIP_LEVEL\n        value: "1"'), 'Render blueprint should document the fast compression default');
assert(readme.includes('ZSIGN_ZIP_LEVEL') && scaling.includes('ZSIGN_ZIP_LEVEL') && html.includes('ZSIGN_ZIP_LEVEL'), 'performance tuning must be documented');

console.log('Performance contract checks passed: configurable fast zsign archiving and conservative default concurrency.');
