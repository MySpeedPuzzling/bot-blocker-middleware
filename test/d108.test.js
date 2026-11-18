// lily.srv D98 (2026-11-16): close the zero-solve bypasses, stop hurting real
// users, make a forced fail-open hard, and log-only telemetry for the rules that
// touch crawlers.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-d108-'));

// GeoDB fixture (same shape as hosting-pass.test.js): 203.0.113.0/24 is a
// datacenter ASN, 198.51.100.0/24 residential, 203.0.113.192/26 also Apple
// Private Relay egress.
const RELAY_IP = '203.0.113.200';
const HOSTING_IP = '203.0.113.10';
const HOME_IP = '198.51.100.20';
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
  const relay = Buffer.alloc(8);
  relay.writeUInt32BE(ip(203, 0, 113, 192), 0);
  relay.writeUInt32BE(ip(203, 0, 113, 255), 4);
  fs.writeFileSync(path.join(dir, 'apple-relay.bin'), relay);
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
process.env.PUZZLE_SCRAPE_THRESHOLD = '100000';
process.env.PROFILE_SCRAPE_THRESHOLD = '100000';
process.env.LOG_DIR = path.join(tmp, 'logs');
fs.mkdirSync(process.env.LOG_DIR, { recursive: true });


const bb = require('../server.js');

// D108: login wall for anonymous Linux desktops on hosting exits, automatic
// loss of trust on account fan-out, manual account block list.

const LINUX_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
const LINUX_FF_UA = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0';
const WINDOWS_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
const ANDROID_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36';
const CROS_UA = 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
const DEEP = '/en/result/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b';

let port;
before(async () => {
  assert.strictEqual(bb.initGeoDb(path.join(tmp, 'geodb')), true);
  await new Promise((resolve) => bb.server.listen(0, '127.0.0.1', resolve));
  port = bb.server.address().port;
});
after(async () => {
  await new Promise((resolve) => bb.server.close(resolve));
});

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function trustCookieValue(uid) {
  const payload = Buffer.from(`bb-trust|v1|${uid}|${Date.now()}`, 'utf8');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest();
  return `__bb_trust=${b64url(payload)}.${b64url(sig)}`;
}

// Coherent, same-origin browser headers: nothing for the risk ladder to score,
// so any 403 here is the login wall (or the account block list).
function request(ip, uri, { ua = LINUX_UA, method = 'GET', cookie, accept } = {}) {
  const headers = {
    'x-forwarded-for': ip,
    'x-forwarded-uri': uri,
    'x-forwarded-method': method,
    'user-agent': ua,
    'accept': accept || 'text/html,application/xhtml+xml',
    'accept-language': 'en-US,en;q=0.9',
    'sec-fetch-site': 'same-origin',
    'sec-ch-ua': '"Chromium";v="157"',
    'referer': 'https://myspeedpuzzling.com/en/puzzles',
  };
  if (cookie) headers.cookie = cookie;
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/', headers }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, reason: res.headers['x-blocked-reason'] || null, body }));
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
const settle = (ms = 50) => new Promise((r) => setTimeout(r, ms));

// --- login wall ---------------------------------------------------------------

test('login wall: anonymous Linux desktop Chrome on a hosting exit gets the login page, not a challenge', async () => {
  const res = await request(HOSTING_IP, DEEP);
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.reason, 'login_wall');
  assert.match(res.body, /id="bb-login"/);
  assert.match(res.body, /Please log in to continue/);
  assert.doesNotMatch(res.body, /cf-turnstile/);
});

test('login wall: Linux Firefox (X11; Ubuntu) on a hosting exit is walled too, page in the URL locale', async () => {
  const res = await request(HOSTING_IP, '/de/ergebnis/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', { ua: LINUX_FF_UA });
  assert.strictEqual(res.reason, 'login_wall');
  assert.match(res.body, /Bitte melde dich an/);
});

test('login wall: never for residential Linux, hosting Windows, Android or ChromeOS', async () => {
  for (const [ip, ua] of [[HOME_IP, LINUX_UA], [HOSTING_IP, WINDOWS_UA], [HOSTING_IP, ANDROID_UA], [HOSTING_IP, CROS_UA]]) {
    const res = await request(ip, DEEP, { ua });
    assert.notStrictEqual(res.reason, 'login_wall', `${ip} ${ua}`);
  }
});

test('login wall: logged-in (trust cookie) Linux on a hosting exit browses normally', async () => {
  const res = await request(HOSTING_IP, DEEP, { cookie: trustCookieValue('linuxuser0000001') });
  assert.strictEqual(res.status, 200);
});

test('login wall: login/register pages, homepages, robots.txt, API and POSTs stay open', async () => {
  for (const uri of ['/en/login', '/login', '/en/register', '/', '/en', '/en/', '/robots.txt', '/sitemap.xml']) {
    const res = await request(HOSTING_IP, uri);
    assert.notStrictEqual(res.reason, 'login_wall', uri);
  }
  const api = await request(HOSTING_IP, '/api/v0/puzzles', { accept: 'application/json' });
  assert.notStrictEqual(api.reason, 'login_wall');
  const post = await request(HOSTING_IP, DEEP, { method: 'POST' });
  assert.notStrictEqual(post.reason, 'login_wall');
});

test('login wall: logged as login_wall with the hosting class', async () => {
  await request(HOSTING_IP, '/en/puzzle/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c');
  await settle();
  const hit = logEntries().find((e) => e.type === 'login_wall');
  assert.ok(hit);
  assert.ok(hit.extra.hosting);
});

// --- automatic loss of trust --------------------------------------------------

test('trust revocation: an account on TRUST_FANOUT_REVOKE networks within the hour loses its trust', async () => {
  assert.strictEqual(bb.TRUST_FANOUT_REVOKE, 15);
  const uid = 'fanoutrevoke0001';
  const cookie = trustCookieValue(uid);
  for (let i = 0; i < 14; i++) {
    assert.strictEqual((await request(`192.0.${i}.7`, DEEP, { ua: WINDOWS_UA, cookie })).status, 200);
  }
  assert.strictEqual(bb.isTrustRevoked(uid), false, '14 networks is still a person');
  await request('192.0.14.7', DEEP, { ua: WINDOWS_UA, cookie });
  assert.strictEqual(bb.isTrustRevoked(uid), true);

  // Now treated as anonymous: on a hosting exit with a Linux desktop it meets the wall.
  const walled = await request(HOSTING_IP, DEEP, { cookie });
  assert.strictEqual(walled.reason, 'login_wall');

  await settle(1200);  // coalesced persistence write
  const entries = logEntries();
  const rev = entries.find((e) => e.type === 'trust_revoked');
  assert.ok(rev);
  assert.strictEqual(rev.extra.uid, uid);
  const saved = JSON.parse(fs.readFileSync(path.join(process.env.LOG_DIR, 'revoked-uids.json'), 'utf8'));
  assert.ok(saved[uid].untilMs > Date.now());
});

test('trust revocation: other accounts are unaffected', async () => {
  const res = await request(HOSTING_IP, DEEP, { cookie: trustCookieValue('innocent00000001') });
  assert.strictEqual(res.status, 200);
});

// --- manual account block list -----------------------------------------------

test('block list: a listed uid with its trust cookie gets 403 uid_blocked; others pass', async () => {
  fs.writeFileSync(path.join(process.env.LOG_DIR, 'blocked-uids.txt'),
    '# scraper account found 2026-11-18\nabcdef0123456789  # note\nnot-a-uid\n');
  bb.reloadBlockedUids();
  const blocked = await request(HOME_IP, DEEP, { ua: WINDOWS_UA, cookie: trustCookieValue('abcdef0123456789') });
  assert.strictEqual(blocked.status, 403);
  assert.strictEqual(blocked.reason, 'uid_blocked');
  const fine = await request(HOME_IP, DEEP, { ua: WINDOWS_UA, cookie: trustCookieValue('0123456789abcdef') });
  assert.strictEqual(fine.status, 200);
});

test('block list: removing the file empties the list', async () => {
  fs.rmSync(path.join(process.env.LOG_DIR, 'blocked-uids.txt'));
  bb.reloadBlockedUids();
  const res = await request(HOME_IP, DEEP, { ua: WINDOWS_UA, cookie: trustCookieValue('abcdef0123456789') });
  assert.strictEqual(res.status, 200);
});
