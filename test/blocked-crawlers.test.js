// Crawlers we block outright by their declared UA token (2026-11-09).
//
// Production Tempo, one hour on 2026-11-09:
//   - Meta's indexing/AI crawlers (meta-webindexer, meta-externalagent) from
//     57.141.20.x: ~2,500 requests/hour, mostly /{locale}/login, /feedback and
//     the social-login start routes - pages with nothing to index. They used to
//     be on the capped whitelist; the per-IP cap does nothing against a fleet.
//   - ShapBot/0.1.0 from Google Cloud: ~100/hour on noindex result-detail pages.
//
// Meta's LINK-PREVIEW fetcher (facebookexternalhit) must keep working: players
// share results on Facebook and the og:image previews depend on it. So must
// meta-externalfetcher (user-initiated fetches), Facebot, Googlebot and humans.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-blocked-crawlers-'));

// GeoDB fixture: 57.141.20.0/24 belongs to AS32934 (Meta), nothing else does.
(function writeMetaGeodb(dir) {
  const ip = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
  const country = Buffer.alloc(9);
  country.writeUInt32BE(ip(57, 141, 20, 0), 0);
  country.writeUInt32BE(ip(57, 141, 20, 255), 4);
  country.writeUInt8(0, 8);
  const asn = Buffer.alloc(10);
  asn.writeUInt32BE(ip(57, 141, 20, 0), 0);
  asn.writeUInt32BE(ip(57, 141, 20, 255), 4);
  asn.writeUInt16BE(0xFFFF, 8);
  const crawler = Buffer.alloc(10);
  crawler.writeUInt32BE(ip(57, 141, 20, 0), 0);
  crawler.writeUInt32BE(ip(57, 141, 20, 255), 4);
  crawler.writeUInt16BE(0, 8);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'country.bin'), country);
  fs.writeFileSync(path.join(dir, 'asn.bin'), asn);
  fs.writeFileSync(path.join(dir, 'crawler-asn.bin'), crawler);
  fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify({
    built: 'test', countries: ['US'], dcOrgs: [], crawlerAsns: [32934],
  }));
})(path.join(tmp, 'geodb'));

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';
process.env.LOG_DIR = path.join(tmp, 'logs');
process.env.GEODB_DIR = path.join(tmp, 'geodb');
fs.mkdirSync(process.env.LOG_DIR, { recursive: true });

const { server, _setDnsForTests, checkWhitelistedBot } = require('../server.js');

const META_IP = '57.141.20.17';
const GCP_IP = '34.122.173.40';

const META_WEBINDEXER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
  + 'Chrome/142.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1; +https://developers.facebook.com/docs/sharing/webmasters/web-crawlers)';
const META_EXTERNALAGENT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0 '
  + '(compatible; meta-externalagent/1.1; +https://developers.facebook.com/docs/sharing/webmasters/web-crawlers)';
const META_EXTERNALAGENT_BARE_UA = 'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)';
const META_WEBINDEXER_BARE_UA = 'meta-webindexer/1.1';
const SHAPBOT_UA = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ShapBot/0.1.0';

const FACEBOOK_PREVIEW_UA = 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)';
const META_FETCHER_UA = 'meta-externalfetcher/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/web-crawlers)';
const FACEBOT_UA = 'Facebot';
const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';
const SAFARI_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1';

let port;
before(async () => {
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
        'x-original-protocol': 'HTTP/2.0',
        'accept': 'text/html',
        'accept-language': 'en',
      },
    }, (res) => {
      res.resume();
      resolve({ status: res.statusCode, reason: res.headers['x-blocked-reason'] || null });
    }).on('error', reject);
  });
}

for (const [label, ua] of [
  ['meta-webindexer (browser-shaped UA)', META_WEBINDEXER_UA],
  ['meta-webindexer (bare UA)', META_WEBINDEXER_BARE_UA],
  ['meta-externalagent (browser-shaped UA)', META_EXTERNALAGENT_UA],
  ['meta-externalagent (bare UA)', META_EXTERNALAGENT_BARE_UA],
]) {
  test(`${label} from Meta's own range is blocked`, async () => {
    for (const uri of ['/en/login', '/cs/feedback', '/en/puzzle/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b']) {
      const res = await forward(META_IP, uri, ua);
      assert.strictEqual(res.status, 403, `${uri} should be 403`);
      assert.match(res.reason, /Meta/);
    }
  });

  test(`${label} is no longer on the crawler whitelist`, async () => {
    assert.strictEqual(await checkWhitelistedBot(ua, META_IP), null);
  });
}

test('ShapBot is blocked on result-detail pages', async () => {
  const res = await forward(GCP_IP, '/en/result/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', SHAPBOT_UA);
  assert.strictEqual(res.status, 403);
  assert.match(res.reason, /ShapBot/);
});

test('ShapBot may still read robots.txt (static, never blocked)', async () => {
  const res = await forward(GCP_IP, '/robots.txt', SHAPBOT_UA);
  assert.strictEqual(res.status, 200);
});

test('a blocked Meta crawler may still read robots.txt', async () => {
  const res = await forward(META_IP, '/robots.txt', META_EXTERNALAGENT_UA);
  assert.strictEqual(res.status, 200);
});

test('facebookexternalhit (link previews) from Meta range is allowed, page and share image', async () => {
  assert.deepStrictEqual(await forward(META_IP, '/en/result/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', FACEBOOK_PREVIEW_UA),
    { status: 200, reason: null });
  assert.deepStrictEqual(await forward(META_IP, '/result-image/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', FACEBOOK_PREVIEW_UA),
    { status: 200, reason: null });
});

test('meta-externalfetcher (user-initiated fetch) is not blocked', async () => {
  assert.deepStrictEqual(await forward('57.141.20.30', '/en/result/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', META_FETCHER_UA),
    { status: 200, reason: null });
});

test('Facebot is not blocked', async () => {
  assert.deepStrictEqual(await forward('57.141.20.31', '/en/result/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', FACEBOT_UA),
    { status: 200, reason: null });
});

test('verified Googlebot is allowed', async () => {
  _setDnsForTests(async () => ['crawl-66-249-66-1.googlebot.com'], async () => ['66.249.66.1']);
  assert.deepStrictEqual(await forward('66.249.66.1', '/en/result/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', GOOGLEBOT_UA),
    { status: 200, reason: null });
});

test('normal browsers are allowed', async () => {
  assert.deepStrictEqual(await forward('198.51.100.7', '/en/login', CHROME_UA), { status: 200, reason: null });
  assert.deepStrictEqual(await forward('198.51.100.8', '/cs/feedback', SAFARI_UA), { status: 200, reason: null });
});

// Decision: no IP-range block. Every Meta crawler announces itself with its
// token (Meta documents the tokens, not "browser UA from our range"), and the
// same /24s carry facebookexternalhit. A token-less browser UA from Meta's
// range is NOT hard-blocked by the UA rules - it goes through the normal
// pipeline (risk scoring sees a datacenter ASN, rate limits apply) like any
// other datacenter visitor, e.g. a Meta employee behind a corporate egress.
test('browser UA without a Meta token from Meta range is not hard-blocked by UA rules', async () => {
  assert.deepStrictEqual(await forward('57.141.20.50', '/en/login', CHROME_UA), { status: 200, reason: null });
});
