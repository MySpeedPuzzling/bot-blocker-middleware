// Short, budgeted passes for hosting exits + the analytics-off header + allow
// sampling (lily.srv D96, 2026-11-16).
//
// The 2026-11-13..15 wave: DigitalOcean exits solved the Turnstile challenge
// ~94% of the time, ISP-proxy pools ~50-70% (humans ~1-2%), and a solved pass
// used to last 7 days while skipping the whole risk ladder. Now:
//   - default pass TTL 24 h; hosting-class exits get 60 min
//   - a pass covers PASS_PAGE_BUDGET (300) / HOSTING_PASS_PAGE_BUDGET (30)
//     scorable pages; past it the request is scored with `pass_exhausted` (+25)
//   - passes living longer than their class allows (the old 7-day ones) are void
//   - an allow for a hosting exit without a trust cookie carries
//     `X-BB-Analytics: off` so the app skips Google Analytics
//   - ALLOW_SAMPLE_RATE of allows are logged as `allow_sample`

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-hosting-pass-'));

// GeoDB fixture: 203.0.113.0/24 = a datacenter ASN ("TestHost"),
// 198.51.100.0/24 = residential (no ASN record), both in the US.
const HOSTING_IP = '203.0.113.10';
const HOSTING_IP_2 = '203.0.113.11';
const HOME_IP = '198.51.100.20';
const HOME_IP_2 = '198.51.100.21';
const HOME_IP_3 = '198.51.100.22';
(function writeGeodb(dir) {
  const ip = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
  const country = Buffer.alloc(18);
  country.writeUInt32BE(ip(198, 51, 100, 0), 0);
  country.writeUInt32BE(ip(198, 51, 100, 255), 4);
  country.writeUInt8(0, 8);
  country.writeUInt32BE(ip(203, 0, 113, 0), 9);
  country.writeUInt32BE(ip(203, 0, 113, 255), 13);
  country.writeUInt8(0, 17);
  const asn = Buffer.alloc(10);
  asn.writeUInt32BE(ip(203, 0, 113, 0), 0);
  asn.writeUInt32BE(ip(203, 0, 113, 255), 4);
  asn.writeUInt16BE(0, 8);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'country.bin'), country);
  fs.writeFileSync(path.join(dir, 'asn.bin'), asn);
  fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify({
    built: 'test', countries: ['US'], dcOrgs: ['TestHost'],
  }));
})(path.join(tmp, 'geodb'));

const SECRET = 'test-secret-for-unit-tests';
process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = SECRET;
process.env.SCORING_MODE = 'challenge';
process.env.ALLOW_SAMPLE_RATE = '1';
process.env.RATE_LIMIT = '100000';
// Keep the scrape/locale detectors out of the way: this file is about passes.
process.env.PUZZLE_SCRAPE_THRESHOLD = '100000';
process.env.PROFILE_SCRAPE_THRESHOLD = '100000';
delete process.env.CHALLENGE_COOKIE_TTL_DAYS;
delete process.env.CHALLENGE_COOKIE_TTL_HOURS;
process.env.LOG_DIR = path.join(tmp, 'logs');
fs.mkdirSync(process.env.LOG_DIR, { recursive: true });

const bb = require('../server.js');

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';

let port;
before(async () => {
  assert.strictEqual(bb.initGeoDb(path.join(tmp, 'geodb')), true);
  await new Promise((resolve) => bb.server.listen(0, '127.0.0.1', resolve));
  port = bb.server.address().port;
});
after(async () => {
  await new Promise((resolve) => bb.server.close(resolve));
});

function passCookieValue(ip, expiresMs) {
  const sig = crypto.createHmac('sha256', SECRET).update(`${ip}|${expiresMs}`).digest('hex');
  return `${bb.CHALLENGE_COOKIE_NAME}=${expiresMs}.${sig}`;
}

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function trustCookieValue(uid) {
  const payload = Buffer.from(`bb-trust|v1|${uid}|${Date.now()}`, 'utf8');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest();
  return `__bb_trust=${b64url(payload)}.${b64url(sig)}`;
}

// A coherent real-Chrome header set: scores 0 on every header signal.
function forward(ip, uri, cookie) {
  const headers = {
    'x-forwarded-for': ip,
    'x-forwarded-uri': uri,
    'x-forwarded-user-agent': CHROME_UA,
    'x-forwarded-method': 'GET',
    'accept': 'text/html,application/xhtml+xml',
    'accept-language': 'en-US,en;q=0.9',
    'sec-fetch-site': 'same-origin',
    'sec-ch-ua': '"Chromium";v="157"',
    'sec-ch-ua-platform': '"Windows"',
    'referer': 'https://myspeedpuzzling.com/en/puzzles',
  };
  if (cookie) headers.cookie = cookie;
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/', headers }, (res) => {
      res.resume();
      resolve({
        status: res.statusCode,
        reason: res.headers['x-blocked-reason'] || null,
        analytics: res.headers['x-bb-analytics'] || null,
      });
    }).on('error', reject);
  });
}

function logEntries() {
  const out = [];
  for (const f of fs.readdirSync(process.env.LOG_DIR)) {
    if (!f.startsWith('blocked-')) continue;
    for (const line of fs.readFileSync(path.join(process.env.LOG_DIR, f), 'utf8').split('\n')) {
      if (line) out.push(JSON.parse(line));
    }
  }
  return out;
}
// logBlocked appends asynchronously.
const settle = () => new Promise((r) => setTimeout(r, 50));

// -----------------------------------------------------------------------------
// Pass lifetime
// -----------------------------------------------------------------------------

test('default pass TTL is 24 h, hosting exits get 60 min', () => {
  assert.strictEqual(bb.CHALLENGE_COOKIE_TTL_MS, 24 * 3600 * 1000);
  assert.strictEqual(bb.hostingClass(HOSTING_IP), 'TestHost');
  assert.strictEqual(bb.hostingClass(HOME_IP), null);
  assert.strictEqual(bb.passTtlFor(HOME_IP), 24 * 3600 * 1000);
  assert.strictEqual(bb.passTtlFor(HOSTING_IP), 60 * 60 * 1000);
});

test('makePassCookie sets Max-Age by class', () => {
  assert.match(bb.makePassCookie(HOME_IP), /Max-Age=86400;/);
  assert.match(bb.makePassCookie(HOSTING_IP), /Max-Age=3600;/);
  const value = bb.makePassCookie(HOSTING_IP).split(';')[0];
  assert.strictEqual(bb.hasValidPassCookie(value, HOSTING_IP), true);
});

test('a 7-day pass minted under the old rules is void, for everyone', () => {
  const sevenDays = Date.now() + 7 * 24 * 3600 * 1000;
  assert.strictEqual(bb.hasValidPassCookie(passCookieValue(HOME_IP, sevenDays), HOME_IP), false);
  assert.strictEqual(bb.hasValidPassCookie(passCookieValue(HOSTING_IP, sevenDays), HOSTING_IP), false);
});

test('a 23 h pass is valid on a residential IP but void on a hosting IP', () => {
  const in23h = Date.now() + 23 * 3600 * 1000;
  assert.strictEqual(bb.hasValidPassCookie(passCookieValue(HOME_IP, in23h), HOME_IP), true);
  assert.strictEqual(bb.hasValidPassCookie(passCookieValue(HOSTING_IP, in23h), HOSTING_IP), false);
});

test('readPassCookie returns a per-pass key; tampering and other IPs still fail', () => {
  const exp = Date.now() + 30 * 60 * 1000;
  const pass = bb.readPassCookie(passCookieValue(HOSTING_IP, exp), HOSTING_IP);
  assert.deepStrictEqual(pass, { key: `${HOSTING_IP}|${exp}`, expiresMs: exp });
  assert.strictEqual(bb.readPassCookie(passCookieValue(HOSTING_IP, exp), HOSTING_IP_2), null);
  assert.strictEqual(bb.readPassCookie(`${passCookieValue(HOSTING_IP, exp)}0`, HOSTING_IP), null);
  assert.strictEqual(bb.readPassCookie(passCookieValue(HOSTING_IP, Date.now() - 1000), HOSTING_IP), null);
});

// -----------------------------------------------------------------------------
// Scoring component
// -----------------------------------------------------------------------------

test('pass_exhausted adds 25; with a datacenter ASN that crosses 60 at calm pressure', () => {
  const headers = {
    'accept-language': 'en', 'sec-fetch-site': 'same-origin', 'sec-ch-ua': 'x',
    'sec-ch-ua-platform': '"Windows"', cookie: 'a=b', referer: 'https://myspeedpuzzling.com/',
  };
  const home = bb.computeRiskScore(HOME_IP, CHROME_UA, '/en/result/x', headers, 0, { passExhausted: true });
  assert.deepStrictEqual(home.components, { pass_exhausted: 25 });
  assert.ok(home.score < bb.SCORE_THRESHOLD);
  const dc = bb.computeRiskScore(HOSTING_IP, CHROME_UA, '/en/result/x', headers, 0, { passExhausted: true });
  assert.deepStrictEqual(dc.components, { pass_exhausted: 25, dc_asn: 40 });
  assert.ok(dc.score >= bb.SCORE_THRESHOLD);
  // Without the option nothing changes for existing callers.
  assert.deepStrictEqual(bb.computeRiskScore(HOME_IP, CHROME_UA, '/en/result/x', headers, 0).components, {});
});

// -----------------------------------------------------------------------------
// End to end through the forwardAuth handler
// -----------------------------------------------------------------------------

test('hosting exit: 30 pages on a pass, then a fresh challenge (analytics off throughout)', async () => {
  const cookie = passCookieValue(HOSTING_IP, Date.now() + 50 * 60 * 1000);
  for (let i = 1; i <= bb.HOSTING_PASS_PAGE_BUDGET; i++) {
    const res = await forward(HOSTING_IP, `/en/result/page-${i}`, cookie);
    assert.strictEqual(res.status, 200, `page ${i} should pass`);
    assert.strictEqual(res.analytics, 'off');
  }
  const over = await forward(HOSTING_IP, '/en/result/page-31', cookie);
  assert.strictEqual(over.status, 403);
  assert.strictEqual(over.reason, 'risk_score');
  await settle();
  const exhausted = logEntries().filter((e) => e.type === 'pass_exhausted' && e.ip === HOSTING_IP);
  assert.strictEqual(exhausted.length, 1);
  assert.deepStrictEqual(exhausted[0].extra, { budget: 30, hosting: 'TestHost' });
  const challenge = logEntries().filter((e) => e.type === 'risk_challenge' && e.ip === HOSTING_IP);
  assert.ok(challenge.at(-1).extra.components.pass_exhausted === 25);
});

test('pages outside the scorable surface do not spend the budget', async () => {
  const cookie = passCookieValue(HOSTING_IP_2, Date.now() + 50 * 60 * 1000);
  for (let i = 0; i < 40; i++) {
    const res = await forward(HOSTING_IP_2, '/api/v1/puzzles', cookie);
    assert.strictEqual(res.status, 200);
  }
  const page = await forward(HOSTING_IP_2, '/en/result/first-page', cookie);
  assert.strictEqual(page.status, 200);
});

test('residential visitor past the 300-page budget is NOT challenged in calm traffic', async () => {
  const cookie = passCookieValue(HOME_IP, Date.now() + 20 * 3600 * 1000);
  for (let i = 1; i <= bb.PASS_PAGE_BUDGET + 5; i++) {
    const res = await forward(HOME_IP, `/en/puzzle/p-${i}`, cookie);
    assert.strictEqual(res.status, 200, `page ${i}`);
    assert.strictEqual(res.analytics, null);
  }
  await settle();
  assert.strictEqual(logEntries().filter((e) => e.type === 'pass_exhausted' && e.ip === HOME_IP).length, 1);
});

test('hosting exit without a pass and clean headers: allowed at calm, analytics off', async () => {
  const res = await forward(HOSTING_IP_2, '/en/ladder', 'other=1');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.analytics, 'off');
});

test('a logged-in user (trust cookie) on a hosting exit keeps analytics', async () => {
  const res = await forward(HOSTING_IP, '/en/result/after-login', trustCookieValue('a1b2c3d4e5f60718'));
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.analytics, null);
});

test('a residential visitor never gets the analytics header', async () => {
  const res = await forward(HOME_IP_2, '/en/ladder', 'other=1');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.analytics, null);
});

// -----------------------------------------------------------------------------
// Allow sampling + summary
// -----------------------------------------------------------------------------

test('allow_sample records via, hosting, score and header facts (no cookie values)', async () => {
  await forward(HOME_IP_3, '/en/result/sampled', `${passCookieValue(HOME_IP_3, Date.now() + 3600 * 1000)}; secret=hunter2`);
  await settle();
  const s = logEntries().filter((e) => e.type === 'allow_sample' && e.ip === HOME_IP_3).at(-1);
  assert.ok(s, 'sample written');
  assert.strictEqual(s.extra.via, 'pass');
  assert.strictEqual(s.extra.hosting, null);
  assert.strictEqual(s.extra.analytics_off, false);
  assert.strictEqual(s.extra.country, 'US');
  assert.strictEqual(s.extra.scorable, true);
  assert.strictEqual(typeof s.extra.score, 'number');
  assert.strictEqual(s.extra.has_cookie, true);
  assert.strictEqual(s.extra.referer_host, 'myspeedpuzzling.com');
  assert.ok(!JSON.stringify(s).includes('hunter2'), 'cookie values never logged');
});

test('daily summary keeps allow_sample out of the blocked totals', async () => {
  const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
  const lines = [
    { type: 'risk_challenge', ip: '1.1.1.1', reason: 'Risk score 70' },
    { type: 'allow_sample', ip: '2.2.2.2', reason: 'Allowed via clean' },
    { type: 'allow_sample', ip: '2.2.2.3', reason: 'Allowed via pass' },
  ].map((e) => JSON.stringify({ timestamp: 'x', userAgent: '', path: '/', ...e })).join('\n');
  fs.writeFileSync(path.join(process.env.LOG_DIR, `blocked-${yesterday}.log`), `${lines}\n`);
  await bb.generateDailySummary();
  const out = fs.readFileSync(path.join(process.env.LOG_DIR, `summary-${yesterday}.txt`), 'utf8');
  assert.match(out, /Total Blocked Requests: 1\n/);
  assert.match(out, /Allowed requests sampled \(allow_sample, not counted above\): 2/);
  assert.ok(!/allow_sample: /.test(out.split('Allowed requests sampled')[1] || ''));
});
