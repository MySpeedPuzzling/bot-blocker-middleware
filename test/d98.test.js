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

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-d98-'));

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

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
const SAFARI_IOS_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1';
const SAFARI_MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15';
const CRIOS_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/157.0.0.0 Mobile/15E148 Safari/604.1';
const APPLE_PREVIEW_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0';

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

function request(ip, uri, { ua = CHROME_UA, method = 'GET', cookie, extra = {}, accept } = {}) {
  const headers = {
    'x-forwarded-for': ip,
    'x-forwarded-uri': uri,
    'x-forwarded-method': method,
    'user-agent': ua,
    'accept': accept || 'text/html,application/xhtml+xml',
    'accept-language': 'en-US,en;q=0.9',
    'sec-fetch-site': 'same-origin',
    'sec-ch-ua': '"Chromium";v="157"',
    'sec-ch-ua-platform': '"Windows"',
    'referer': 'https://myspeedpuzzling.com/en/puzzles',
    ...extra,
  };
  if (cookie) headers.cookie = cookie;
  return new Promise((resolve, reject) => {
    const started = process.hrtime.bigint();
    http.get({ host: '127.0.0.1', port, path: '/', headers }, (res) => {
      res.resume();
      res.on('end', () => resolve({
        status: res.statusCode,
        reason: res.headers['x-blocked-reason'] || null,
        ms: Number(process.hrtime.bigint() - started) / 1e6,
      }));
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
const settle = () => new Promise((r) => setTimeout(r, 50));

// --- 0.3 crafted pass cookie -------------------------------------------------

test('a multi-byte pass signature is "no pass", never a thrown error', () => {
  const expires = Date.now() + 60_000;
  const crafted = `${bb.CHALLENGE_COOKIE_NAME}=${expires}.${'é'.repeat(64)}`;
  assert.doesNotThrow(() => bb.readPassCookie(crafted, HOME_IP));
  assert.strictEqual(bb.readPassCookie(crafted, HOME_IP), null);
  // wrong-case / wrong-length hex is rejected too
  assert.strictEqual(bb.readPassCookie(`${bb.CHALLENGE_COOKIE_NAME}=${expires}.${'A'.repeat(64)}`, HOME_IP), null);
  assert.strictEqual(bb.readPassCookie(`${bb.CHALLENGE_COOKIE_NAME}=${expires}.${'a'.repeat(63)}`, HOME_IP), null);
});

test('E2E: the crafted cookie no longer turns a blocked path into a 200', async () => {
  const expires = Date.now() + 60_000;
  const crafted = `${bb.CHALLENGE_COOKIE_NAME}=${expires}.${'é'.repeat(64)}`;
  const res = await request(HOME_IP, '/.env', { cookie: crafted });
  assert.strictEqual(res.status, 403);
});

test('a genuine pass cookie still validates', () => {
  const cookie = bb.makePassCookie(HOME_IP).split(';')[0];
  assert.notStrictEqual(bb.readPassCookie(cookie, HOME_IP), null);
});

// --- 0.2 UA header + Stripe --------------------------------------------------

test('E2E: X-Forwarded-User-Agent is ignored (a client cannot claim Stripe to us)', async () => {
  const res = await request(HOME_IP, '/.env', {
    ua: 'Mozilla/5.0 (compatible; GPTBot/1.0)',
    extra: { 'x-forwarded-user-agent': 'Stripe/1.0 (+https://stripe.com/docs/webhooks)' },
  });
  assert.strictEqual(res.status, 403);
});

test('E2E: Stripe UA passes only as POST /webhook/stripe', async () => {
  const stripe = 'Stripe/1.0 (+https://stripe.com/docs/webhooks)';
  assert.strictEqual((await request(HOSTING_IP, '/webhook/stripe', { ua: stripe, method: 'POST' })).status, 200);
  // A path rule still applies to the Stripe UA elsewhere
  assert.strictEqual((await request(HOSTING_IP, '/.env', { ua: stripe })).status, 403);
});

// --- 0.10 forced fail-open ---------------------------------------------------

test('E2E: an 8 KB UA is truncated and answered fast, never a crash', async () => {
  assert.strictEqual(bb.MAX_UA_LENGTH, 512);
  const longUa = 'Mozilla/5.0 ' + 'a(b'.repeat(2700);
  const res = await request(HOME_IP, '/', { ua: longUa });
  assert.ok([200, 403].includes(res.status), `status ${res.status}`);
  assert.ok(res.ms < 200, `took ${res.ms} ms`);
});

test('capMap evicts the oldest insertions', () => {
  const m = new Map();
  for (let i = 0; i < 10; i++) {
    m.set(i, i);
    bb.capMap(m, 5);
  }
  assert.deepStrictEqual([...m.keys()], [5, 6, 7, 8, 9]);
});

// --- 0.8 Private Relay -------------------------------------------------------

test('Safari on Private Relay egress no longer scores dc_asn; others still do', () => {
  const headers = { 'accept-language': 'en-US', referer: 'https://myspeedpuzzling.com/' };
  const relaySafari = bb.computeRiskScore(RELAY_IP, SAFARI_IOS_UA, '/en/puzzle/x', headers, 0);
  assert.strictEqual(relaySafari.components.dc_asn, undefined);
  const relayMac = bb.computeRiskScore(RELAY_IP, SAFARI_MAC_UA, '/en/puzzle/x', headers, 0);
  assert.strictEqual(relayMac.components.dc_asn, undefined);
  // Chrome on iOS (CriOS) cannot use Private Relay — relay-listed but not exempt
  assert.ok(bb.computeRiskScore(RELAY_IP, CRIOS_UA, '/en/puzzle/x', headers, 0).components.dc_asn > 0);
  assert.ok(bb.computeRiskScore(RELAY_IP, CHROME_UA, '/en/puzzle/x', headers, 0).components.dc_asn > 0);
  // Safari on a plain datacenter IP still scores
  assert.ok(bb.computeRiskScore(HOSTING_IP, SAFARI_IOS_UA, '/en/puzzle/x', headers, 0).components.dc_asn > 0);
});

test('isSafariFamilyUa: Safari yes; Chrome, CriOS, Firefox iOS, Edge, Apple preview no', () => {
  assert.strictEqual(bb.isSafariFamilyUa(SAFARI_IOS_UA), true);
  assert.strictEqual(bb.isSafariFamilyUa(SAFARI_MAC_UA), true);
  for (const ua of [CHROME_UA, CRIOS_UA, APPLE_PREVIEW_UA,
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0']) {
    assert.strictEqual(bb.isSafariFamilyUa(ua), false, ua);
  }
});

// --- 0.9 Apple link preview --------------------------------------------------

test('Apple link preview is allowed with a 10/min per-IP cap', async () => {
  const ip = '198.51.100.90';
  for (let i = 0; i < 10; i++) {
    assert.deepStrictEqual(await bb.checkWhitelistedBot(APPLE_PREVIEW_UA, ip), { name: 'Apple link preview', allow: true });
  }
  assert.deepStrictEqual(await bb.checkWhitelistedBot(APPLE_PREVIEW_UA, ip), { name: 'Apple link preview', capped: true });
  // A plain facebookexternalhit UA from the same network still meets the Meta check
  const plainFb = await bb.checkWhitelistedBot('facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)', '198.51.100.91');
  assert.notStrictEqual(plainFb && plainFb.name, 'Apple link preview');
});

// --- Sitemaps / Accept bypass telemetry -------------------------------------

test('sitemaps are never scored', () => {
  for (const p of ['/sitemap.xml', '/sitemap-puzzles-1.xml', '/sitemap_index.xml?x=1']) {
    assert.strictEqual(bb.isScorableRequest({ accept: 'text/html' }, p), false, p);
  }
  assert.strictEqual(bb.isScorableRequest({ accept: 'text/html' }, '/en/puzzle/x'), true);
});

test('isAcceptBypass: a JSON Accept on a page route counts, on API/component routes it does not', () => {
  const json = { accept: 'application/json' };
  assert.strictEqual(bb.isAcceptBypass(json, '/en/puzzle/abc'), true);
  assert.strictEqual(bb.isAcceptBypass(json, '/api/v0/x'), false);
  assert.strictEqual(bb.isAcceptBypass(json, '/_components/PuzzleTimes'), false);
  assert.strictEqual(bb.isAcceptBypass({ accept: '*/*' }, '/en/puzzle/abc'), false);
  assert.strictEqual(bb.isAcceptBypass({ ...json, 'x-forwarded-method': 'POST' }, '/en/puzzle/abc'), false);
});

test('E2E: a bot-grade JSON-Accept GET is still allowed today but logged as would_score', async () => {
  const res = await request(HOSTING_IP, '/en/puzzle/abcdef', {
    accept: 'application/json',
    extra: { 'sec-fetch-site': '', 'sec-ch-ua': '', 'accept-language': '', referer: '' },
  });
  assert.strictEqual(res.status, 200);
  await settle();
  const hit = logEntries().find((e) => e.type === 'would_score' && e.extra?.rule === 'non_html_accept');
  assert.ok(hit, 'would_score non_html_accept logged');
  assert.strictEqual(hit.path, '/en/puzzle/abcdef');
});

// --- Trust fan-out telemetry --------------------------------------------------

test('E2E: trust allows carry the uid in allow_sample; a uid on 10 networks logs would_deny', async () => {
  const cookie = trustCookieValue('fanoutuid0000001');
  for (let i = 0; i < 10; i++) {
    const res = await request(`192.0.${i}.7`, '/en/ladder', { cookie });
    assert.strictEqual(res.status, 200);
  }
  await settle();
  const entries = logEntries();
  assert.ok(entries.some((e) => e.type === 'allow_sample' && e.extra?.uid === 'fanoutuid0000001'));
  const fan = entries.find((e) => e.type === 'would_deny' && e.extra?.rule === 'trust_fanout');
  assert.ok(fan, 'trust_fanout logged');
  assert.strictEqual(fan.extra.networks, 10);
});

// --- rDNS error handling ------------------------------------------------------

test('rDNS error: never-verified IP is allowed but logged; a known crawler keeps its last ok verdict', async () => {
  const err = Object.assign(new Error('servfail'), { code: 'ESERVFAIL' });
  bb._setDnsForTests(async () => { throw err; }, async () => []);
  const r1 = await bb.checkWhitelistedBot('Mozilla/5.0 (compatible; SeznamBot/4.0; +https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/)', '198.51.100.120');
  assert.deepStrictEqual(r1, { name: 'Seznam', allow: true });
  await settle();
  assert.ok(logEntries().some((e) => e.type === 'would_cap' && e.extra?.rule === 'rdns_error_unverified' && e.ip === '198.51.100.120'));

  // verify once successfully, then fail: the IP stays verified
  bb._setDnsForTests(async () => ['fulltextrobot-77-75-77-1.seznam.cz'], async () => ['198.51.100.121']);
  assert.strictEqual(await bb.verifyCrawlerRdns('198.51.100.121', ['.seznam.cz']), 'ok');
  // the resolver now fails (verdict cache cleared, last-ok memory kept): still ok
  bb._setDnsForTests(async () => { throw err; }, async () => [], false);
  assert.strictEqual(await bb.verifyCrawlerRdns('198.51.100.121', ['.seznam.cz']), 'ok');
  // ...while an IP that never verified gets 'error'
  assert.strictEqual(await bb.verifyCrawlerRdns('198.51.100.122', ['.seznam.cz']), 'error');
});
