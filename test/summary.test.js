// Unit tests for the daily block summary.
//
// This file exists because of a production outage: the original implementation
// did `fs.readFileSync(wholeDayLog)` + `.split('\n')`. Once enforcement went
// live a day's log reached 167 MB, so the summary run at 00:05 UTC blew through
// the container's 256 MB limit and the kernel OOM-killed the process — on
// 2026-08-04 AND 2026-08-05. Every in-memory counter (permabans, rate limits,
// rDNS cache) was lost nightly and no summary was ever written.
//
// The guards below pin the two properties that prevent a recurrence:
//   1. the log is STREAMED, so peak memory does not track file size;
//   2. reason keys are COLLAPSED, so the histogram cannot grow one bucket per
//      request (that bug made a 425 KB "summary" out of a 1.5 KB report).

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';

const LOG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-summary-'));
process.env.LOG_DIR = LOG_DIR;

const { generateDailySummary, summaryReasonKey } = require('../server.js');

function yesterdayStamp() {
  return new Date(Date.now() - 86400000).toISOString().split('T')[0];
}

function writeLog(entries) {
  const file = path.join(LOG_DIR, `blocked-${yesterdayStamp()}.log`);
  fs.writeFileSync(file, entries.map(e => JSON.stringify(e)).join('\n') + '\n');
  return file;
}

function readSummary() {
  return fs.readFileSync(path.join(LOG_DIR, `summary-${yesterdayStamp()}.txt`), 'utf8');
}

// -----------------------------------------------------------------------------
// Reason-key collapsing
// -----------------------------------------------------------------------------

test('per-request numbers collapse so the histogram stays bounded', () => {
  const a = summaryReasonKey('Risk score 117 (base 50 x pressure 2.33)');
  const b = summaryReasonKey('Risk score 284 (base 120 x pressure 2.36)');
  assert.strictEqual(a, b, 'two risk scores must share one bucket');

  const s1 = summaryReasonKey('Tencent Cloud botnet range (43.172.0.0/15)');
  const s2 = summaryReasonKey('Tencent Cloud botnet range (202.46.62.0/24)');
  assert.strictEqual(s1, s2);

  // Distinct RULES still stay distinct.
  assert.notStrictEqual(summaryReasonKey('Too many requests'),
    summaryReasonKey('Risk score 70 (base 30 x pressure 2.33)'));
  assert.strictEqual(summaryReasonKey(undefined), '(none)');
  assert.ok(summaryReasonKey('x'.repeat(500)).length <= 120);
});

// -----------------------------------------------------------------------------
// Summary content
// -----------------------------------------------------------------------------

test('summary counts types, reasons and top IPs', async () => {
  writeLog([
    { type: 'risk_challenge', ip: '1.1.1.1', reason: 'Risk score 70 (base 30 x pressure 2.3)' },
    { type: 'risk_challenge', ip: '1.1.1.1', reason: 'Risk score 91 (base 40 x pressure 2.3)' },
    { type: 'risk_challenge', ip: '2.2.2.2', reason: 'Risk score 91 (base 40 x pressure 2.3)' },
    { type: 'rate_limit', ip: '3.3.3.3', reason: 'Too many requests' },
  ]);
  await generateDailySummary();
  const out = readSummary();

  assert.match(out, /Total Blocked Requests: 4/);
  assert.match(out, /risk_challenge: 3/);
  assert.match(out, /rate_limit: 1/);
  assert.match(out, /1\.1\.1\.1: 2/);
  // All three risk scores collapsed into ONE reason bucket.
  assert.match(out, /Risk score N \(base N x pressure N\.N\): 3/);
});

test('malformed lines are counted, not fatal', async () => {
  const file = writeLog([{ type: 'bot', ip: '9.9.9.9', reason: 'Dead device' }]);
  fs.appendFileSync(file, 'not json at all\n{"truncated":\n');
  await generateDailySummary();
  const out = readSummary();
  assert.match(out, /Total Blocked Requests: 1/);
  assert.match(out, /Malformed log lines skipped: 2/);
});

test('a missing log file is a no-op, not a crash', async () => {
  const file = path.join(LOG_DIR, `blocked-${yesterdayStamp()}.log`);
  const summary = path.join(LOG_DIR, `summary-${yesterdayStamp()}.txt`);
  fs.rmSync(file, { force: true });
  fs.rmSync(summary, { force: true });
  await generateDailySummary();
  assert.strictEqual(fs.existsSync(summary), false);
});

// -----------------------------------------------------------------------------
// The OOM guard itself
// -----------------------------------------------------------------------------

test('a large log is summarised without loading it into memory', async () => {
  // ~40 MB / 200k lines: with the old readFileSync+split this allocated the
  // file as a Buffer, again as a string, and again as a 200k-element array.
  // Streaming keeps the heap flat, which is what the assertion below measures.
  const file = path.join(LOG_DIR, `blocked-${yesterdayStamp()}.log`);
  const fh = fs.openSync(file, 'w');
  const chunk = [];
  for (let i = 0; i < 1000; i++) {
    chunk.push(JSON.stringify({
      type: 'risk_challenge',
      ip: `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0',
      reason: `Risk score ${60 + (i % 300)} (base ${30 + (i % 100)} x pressure 2.33)`,
      path: `/en/puzzle/0191a13c-eba1-73cc-8245-cffb728${String(i).padStart(5, '0')}`,
    }));
  }
  const block = chunk.join('\n') + '\n';
  for (let i = 0; i < 200; i++) fs.writeSync(fh, block);
  fs.closeSync(fh);

  const sizeMb = fs.statSync(file).size / 1048576;
  assert.ok(sizeMb > 30, `fixture should be big, got ${sizeMb.toFixed(1)} MB`);

  global.gc?.();
  const before = process.memoryUsage().heapUsed;
  await generateDailySummary();
  const grew = (process.memoryUsage().heapUsed - before) / 1048576;

  const out = readSummary();
  assert.match(out, /Total Blocked Requests: 200000/);
  // The IP table (1000 distinct) is the only thing that legitimately grows.
  // The old implementation grew by well over the file size; allow generous
  // headroom and still catch a regression to slurping.
  assert.ok(grew < sizeMb, `heap grew ${grew.toFixed(1)} MB for a ${sizeMb.toFixed(1)} MB file`);

  fs.rmSync(file, { force: true });
});
