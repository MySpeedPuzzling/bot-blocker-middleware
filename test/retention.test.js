// Block-log retention and the health endpoint.
//
// The sidecar wrote one `blocked-YYYY-MM-DD.log` per day and never removed any:
// 119 files / 5.5 GB by 2026-11-15. These tests pin what the pruning may and may
// not touch - the summaries are the long-term history and banned-ips.json is
// live state, so neither may ever be removed.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';

const LOG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-retention-'));
process.env.LOG_DIR = LOG_DIR;

const { server, pruneOldBlockLogs, LOG_RETENTION_DAYS, HEALTH_PATH } = require('../server.js');

const NOW = Date.parse('2026-11-15T23:30:00Z');

function touch(name) {
  fs.writeFileSync(path.join(LOG_DIR, name), 'x\n');
}

function reset() {
  for (const name of fs.readdirSync(LOG_DIR)) fs.unlinkSync(path.join(LOG_DIR, name));
}

test('default retention is 14 days', () => {
  assert.strictEqual(LOG_RETENTION_DAYS, 14);
});

test('removes block logs older than the window, by the date in the name', async () => {
  reset();
  touch('blocked-2026-11-15.log'); // today
  touch('blocked-2026-11-01.log'); // exactly 14 days back: kept
  touch('blocked-2026-10-31.log'); // 15 days back: removed
  touch('blocked-2026-08-03.log'); // old: removed

  const removed = await pruneOldBlockLogs(NOW, 14);

  assert.deepStrictEqual(removed.sort(), ['blocked-2026-08-03.log', 'blocked-2026-10-31.log']);
  assert.deepStrictEqual(fs.readdirSync(LOG_DIR).sort(), ['blocked-2026-11-01.log', 'blocked-2026-11-15.log']);
});

test('never touches summaries, the ban list or foreign files', async () => {
  reset();
  touch('summary-2026-06-20.txt');
  touch('banned-ips.json');
  touch('blocked-2026-06-20.log.bak');
  touch('notes-blocked-2026-06-20.log');
  touch('blocked-2026-06-20.log');

  const removed = await pruneOldBlockLogs(NOW, 14);

  assert.deepStrictEqual(removed, ['blocked-2026-06-20.log']);
  assert.deepStrictEqual(fs.readdirSync(LOG_DIR).sort(), [
    'banned-ips.json',
    'blocked-2026-06-20.log.bak',
    'notes-blocked-2026-06-20.log',
    'summary-2026-06-20.txt',
  ]);
});

test('retention 0 keeps everything', async () => {
  reset();
  touch('blocked-2020-01-01.log');

  assert.deepStrictEqual(await pruneOldBlockLogs(NOW, 0), []);
  assert.deepStrictEqual(fs.readdirSync(LOG_DIR), ['blocked-2020-01-01.log']);
});

test('a missing log directory is not an error', async () => {
  reset();
  fs.rmdirSync(LOG_DIR);
  assert.deepStrictEqual(await pruneOldBlockLogs(NOW, 14), []);
  fs.mkdirSync(LOG_DIR);
});

function get(port, urlPath, headers) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: urlPath, headers }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

test('health endpoint answers a direct request, and only a direct one', async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    const direct = await get(port, HEALTH_PATH, {});
    assert.strictEqual(direct.status, 200);
    assert.strictEqual(direct.body, 'ok');

    // What a visitor asking for /-/healthz looks like to the sidecar: Traefik
    // calls `/` and passes the path along. That is an ordinary page request and
    // must go through the normal pipeline (an empty UA is not waved through as "ok").
    const viaEdge = await get(port, '/', { 'x-forwarded-uri': HEALTH_PATH, 'x-forwarded-for': '203.0.113.9' });
    assert.notStrictEqual(viaEdge.body, 'ok');

    // A direct call that carries a forwarded path is not the healthcheck either.
    const spoof = await get(port, HEALTH_PATH, { 'x-forwarded-uri': '/en/puzzle', 'x-forwarded-for': '203.0.113.9' });
    assert.notStrictEqual(spoof.body, 'ok');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
