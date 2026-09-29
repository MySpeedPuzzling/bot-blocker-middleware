// Google's published fetcher ranges (IP-verified, UA-independent) and the
// risk-ladder exempt paths (home + legal pages reviewers fetch).
//
// Regression for 2026-09-29: Google's OAuth brand-verification fetcher
// (UA "Google", 66.249.83.33/35 — user-triggered-fetchers-google) got the
// Turnstile challenge on / and /en/privacy-policy and the brand review failed.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-google-'));
fs.writeFileSync(path.join(tmp, 'google-ranges.json'), JSON.stringify({
  built: '2026-09-29T00:00:00Z',
  lists: {
    'user-triggered-fetchers-google': ['66.249.83.32/27', '2001:4860:4801:2008::/64'],
    'common-crawlers': ['192.178.4.0/27'],
  },
}));

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';
process.env.SCORING_MODE = 'challenge';
process.env.WHITELIST_BOT_CAP = '5';
process.env.LOG_DIR = path.join(tmp, 'logs');
process.env.GEODB_DIR = path.join(tmp, 'no-geodb');
fs.mkdirSync(process.env.LOG_DIR, { recursive: true });

const {
  server, parseGoogleRangeDocument, setGoogleRanges, loadGoogleRanges,
  refreshGoogleRanges, isGooglePublishedIp, isScoringExemptPath,
} = require('../server.js');

// Mobile Chrome without Sec-Fetch-* / sec-ch-ua — what Read Aloud sends; scores
// no_sec_fetch 40 + no_sec_ch_ua 30 = 70 >= threshold 60 on a deep path.
const READ_ALOUD_UA = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) '
  + 'Chrome/138.0.0.0 Mobile Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)';

let port;
before(async () => {
  loadGoogleRanges(tmp);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
});
after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

function forward(ip, uri, ua) {
  return new Promise((resolve, reject) => {
    http.get({
      host: '127.0.0.1', port, path: '/',
      headers: {
        'x-forwarded-for': ip,
        'x-forwarded-uri': uri,
        'x-forwarded-user-agent': ua,
        'x-forwarded-method': 'GET',
        'accept': 'text/html',
        'accept-language': 'en',
      },
    }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
  });
}

test('parses Google range documents, rejects junk', () => {
  assert.deepStrictEqual(parseGoogleRangeDocument({
    creationTime: 'x',
    prefixes: [{ ipv4Prefix: '1.2.3.0/27' }, { ipv6Prefix: '2001:db8::/64' }, { foo: 1 }, { ipv4Prefix: 'evil' }],
  }), ['1.2.3.0/27', '2001:db8::/64']);
  assert.strictEqual(parseGoogleRangeDocument({}), null);
  assert.strictEqual(parseGoogleRangeDocument(null), null);
});

test('baked ranges: IPv4, IPv6 and IPv4-mapped membership', () => {
  assert.strictEqual(isGooglePublishedIp('66.249.83.33'), true);
  assert.strictEqual(isGooglePublishedIp('66.249.83.35'), true);
  assert.strictEqual(isGooglePublishedIp('::ffff:66.249.83.33'), true);
  assert.strictEqual(isGooglePublishedIp('2001:4860:4801:2008::1'), true);
  assert.strictEqual(isGooglePublishedIp('66.249.83.64'), false);   // outside the /27
  assert.strictEqual(isGooglePublishedIp('35.196.155.190'), false); // plain GCP VM
  assert.strictEqual(isGooglePublishedIp('not-an-ip'), false);
  assert.strictEqual(isGooglePublishedIp(undefined), false);
});

test('refresh merges per list and keeps previous data for failed lists', async () => {
  const fakeFetch = async (url) => {
    if (url.endsWith('/common-crawlers.json')) {
      return { ok: true, json: async () => ({ prefixes: [{ ipv4Prefix: '203.0.113.0/27' }] }) };
    }
    if (url.endsWith('/special-crawlers.json')) return { ok: false, status: 503 };
    if (url.endsWith('/user-triggered-fetchers.json')) throw new Error('network down');
    return { ok: true, json: async () => ({ prefixes: [] }) };  // empty = ignored
  };
  await refreshGoogleRanges(fakeFetch);
  assert.strictEqual(isGooglePublishedIp('203.0.113.5'), true, 'refreshed list applied');
  assert.strictEqual(isGooglePublishedIp('192.178.4.1'), false, 'replaced list dropped old prefix');
  assert.strictEqual(isGooglePublishedIp('66.249.83.33'), true, 'empty refresh kept baked list');
  // restore the baked state for the other tests
  loadGoogleRanges(tmp);
});

test('setGoogleRanges ignores empty input', () => {
  assert.strictEqual(setGoogleRanges({}, 'x'), false);
  assert.strictEqual(setGoogleRanges({ a: [] }, 'x'), false);
});

test('ladder-exempt paths: home + legal pages in every locale, nothing deeper', () => {
  for (const p of ['/', '/en', '/cs/', '/en/privacy-policy', '/en/privacy-policy?utm=x',
    '/zasady-ochrany-osobnich-udaju', '/en/terms-of-service', '/en/data-deletion',
    '/de/datenloeschung', '/ja/%E3%83%97%E3%83%A9%E3%82%A4%E3%83%90%E3%82%B7%E3%83%BC']) {
    assert.strictEqual(isScoringExemptPath(p), true, p);
  }
  for (const p of ['/en/puzzle/123', '/en/privacy-policy/x', '/en/privacy', '/%E0%A4%A']) {
    assert.strictEqual(isScoringExemptPath(p), false, p);
  }
});

test('E2E: Google fetcher range passes on a deep page; same request elsewhere is challenged', async () => {
  assert.strictEqual(await forward('66.249.83.40', '/en/puzzle/abc', READ_ALOUD_UA), 200);
  assert.strictEqual(await forward('198.51.100.10', '/en/puzzle/abc', READ_ALOUD_UA), 403);
});

test('E2E: brand-verification fetcher (UA "Google") gets home + privacy policy', async () => {
  assert.strictEqual(await forward('66.249.83.33', '/en/privacy-policy', 'Google'), 200);
  assert.strictEqual(await forward('66.249.83.35', '/', 'Google'), 200);
});

test('E2E: legal pages are not challenged by the ladder from any IP', async () => {
  assert.strictEqual(await forward('198.51.100.11', '/en/privacy-policy', READ_ALOUD_UA), 200);
  assert.strictEqual(await forward('198.51.100.11', '/', READ_ALOUD_UA), 200);
  // ...but deterministic rules still apply there
  assert.strictEqual(await forward('198.51.100.12', '/en/privacy-policy', 'Mozilla/5.0 (compatible; GPTBot/1.0)'), 403);
});

test('E2E: Google range is capped per IP', async () => {
  const codes = [];
  for (let i = 0; i < 7; i++) codes.push(await forward('66.249.83.50', '/en/puzzle/x' + i, 'Google'));
  assert.deepStrictEqual(codes, [200, 200, 200, 200, 200, 429, 429]);
});
