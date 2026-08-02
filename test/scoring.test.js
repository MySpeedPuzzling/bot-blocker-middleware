// Unit tests for the risk-scoring ladder (D50): surface eligibility, each
// signal in isolation, the pressure multiplier, and the GeoDB range reader
// (via a hand-built fixture in the documented binary format).

const { test, before } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';
// Deterministic scoring knobs regardless of future default changes.
process.env.SURGE_BASELINE_5M = '300';
process.env.SURGE_EXTRA_SCORE = '20';
process.env.HIGH_RISK_COUNTRIES = 'CN,HK,SG,VN,ID';

const {
  computeRiskScore, isScorableRequest, uaOsFamily, SCORE_WEIGHTS,
  initGeoDb, geoCountry, asnDatacenterOrg,
} = require('../server.js');

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36';
const SAFARI_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1';

// A fully coherent real-Chrome header set — the baseline that must score 0.
function coherentHeaders(overrides = {}) {
  return {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': 'cs-CZ,cs;q=0.9,en;q=0.8',
    'sec-fetch-site': 'none',
    'sec-fetch-mode': 'navigate',
    'sec-ch-ua': '"Chromium";v="150", "Google Chrome";v="150"',
    'sec-ch-ua-platform': '"Windows"',
    'cookie': 'PHPSESSID=abc',
    ...overrides,
  };
}

// -----------------------------------------------------------------------------
// GeoDB fixture: 198.18.0.0/24 -> CN + "Test DC Org"; 198.18.1.0/24 -> CZ, no DC
// -----------------------------------------------------------------------------

before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geodb-test-'));
  const ip = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

  const country = Buffer.alloc(2 * 9);
  country.writeUInt32BE(ip(198, 18, 0, 0), 0);
  country.writeUInt32BE(ip(198, 18, 0, 255), 4);
  country.writeUInt8(0, 8);   // CN
  country.writeUInt32BE(ip(198, 18, 1, 0), 9);
  country.writeUInt32BE(ip(198, 18, 1, 255), 13);
  country.writeUInt8(1, 17);  // CZ

  const asn = Buffer.alloc(2 * 10);
  asn.writeUInt32BE(ip(198, 18, 0, 0), 0);
  asn.writeUInt32BE(ip(198, 18, 0, 255), 4);
  asn.writeUInt16BE(0, 8);       // Test DC Org
  asn.writeUInt32BE(ip(198, 18, 1, 0), 10);
  asn.writeUInt32BE(ip(198, 18, 1, 255), 14);
  asn.writeUInt16BE(0xFFFF, 18); // not a datacenter

  fs.writeFileSync(path.join(dir, 'country.bin'), country);
  fs.writeFileSync(path.join(dir, 'asn.bin'), asn);
  fs.writeFileSync(path.join(dir, 'meta.json'),
    JSON.stringify({ built: 'test', countries: ['CN', 'CZ'], dcOrgs: ['Test DC Org'] }));
  assert.strictEqual(initGeoDb(dir), true);
});

test('geodb reader resolves country and datacenter org from fixture', () => {
  assert.strictEqual(geoCountry('198.18.0.42'), 'CN');
  assert.strictEqual(asnDatacenterOrg('198.18.0.42'), 'Test DC Org');
  assert.strictEqual(geoCountry('198.18.1.42'), 'CZ');
  assert.strictEqual(asnDatacenterOrg('198.18.1.42'), null);
  assert.strictEqual(geoCountry('203.0.113.1'), null);
});

// -----------------------------------------------------------------------------
// Surface eligibility
// -----------------------------------------------------------------------------

test('isScorableRequest: anonymous HTML GETs only', () => {
  const html = coherentHeaders();
  assert.strictEqual(isScorableRequest(html, '/en/puzzles'), true);
  assert.strictEqual(isScorableRequest({ ...html, 'x-forwarded-method': 'POST' }, '/en/puzzles'), false);
  assert.strictEqual(isScorableRequest(html, '/api/v1/times'), false);
  assert.strictEqual(isScorableRequest(html, '/webhook/stripe'), false);
  assert.strictEqual(isScorableRequest(html, '/-/health-check/liveness'), false);
  assert.strictEqual(isScorableRequest(html, '/.well-known/mercure'), false);
  assert.strictEqual(isScorableRequest({ ...html, accept: 'application/json' }, '/en/puzzles'), false);
  assert.strictEqual(isScorableRequest({ ...html, accept: '*/*' }, '/en/puzzles'), true);
  assert.strictEqual(isScorableRequest({ ...html, accept: '' }, '/en/puzzles'), true);
});

// -----------------------------------------------------------------------------
// Individual signals
// -----------------------------------------------------------------------------

test('coherent real-browser request scores 0', () => {
  const risk = computeRiskScore('203.0.113.10', CHROME_UA, '/puzzle/abc', coherentHeaders(), 10);
  assert.strictEqual(risk.score, 0);
  assert.deepStrictEqual(risk.components, {});
});

test('datacenter ASN scores dc_asn', () => {
  const risk = computeRiskScore('198.18.0.42', CHROME_UA, '/puzzle/abc',
    coherentHeaders({ 'accept-language': 'zh-CN,zh;q=0.9' }), 10);
  assert.strictEqual(risk.components.dc_asn, SCORE_WEIGHTS.dc_asn);
  // CN fixture country also fires the audience prior
  assert.strictEqual(risk.components.high_risk_country, SCORE_WEIGHTS.high_risk_country);
});

test('curated cloud CIDRs fire dc_cidr without GeoDB coverage', () => {
  // 129.226.0.0/16 is Tencent Cloud in CLOUD_PROVIDER_CIDRS
  const risk = computeRiskScore('129.226.1.1', CHROME_UA, '/puzzle/abc', coherentHeaders(), 10);
  assert.strictEqual(risk.components.dc_cidr, SCORE_WEIGHTS.dc_cidr);
});

test('claimed modern Chrome without Sec-Fetch/sec-ch-ua is impossible', () => {
  const headers = coherentHeaders();
  delete headers['sec-fetch-site'];
  delete headers['sec-ch-ua'];
  delete headers['sec-ch-ua-platform'];
  const risk = computeRiskScore('203.0.113.10', CHROME_UA, '/puzzle/abc', headers, 10);
  assert.strictEqual(risk.components.no_sec_fetch, SCORE_WEIGHTS.no_sec_fetch);
  assert.strictEqual(risk.components.no_sec_ch_ua, SCORE_WEIGHTS.no_sec_ch_ua);
});

test('Safari is never scored on Chromium-only headers', () => {
  const headers = coherentHeaders();
  delete headers['sec-fetch-site'];
  delete headers['sec-ch-ua'];
  delete headers['sec-ch-ua-platform'];
  const risk = computeRiskScore('203.0.113.10', SAFARI_UA, '/puzzle/abc', headers, 10);
  assert.strictEqual(risk.components.no_sec_fetch, undefined);
  assert.strictEqual(risk.components.no_sec_ch_ua, undefined);
});

test('sec-ch-ua-platform contradicting the UA OS is flagged', () => {
  const risk = computeRiskScore('203.0.113.10', CHROME_UA, '/puzzle/abc',
    coherentHeaders({ 'sec-ch-ua-platform': '"Linux"' }), 10);
  assert.strictEqual(risk.components.platform_mismatch, SCORE_WEIGHTS.platform_mismatch);
});

test('browser-like UA without Accept-Language is flagged', () => {
  const headers = coherentHeaders();
  delete headers['accept-language'];
  const risk = computeRiskScore('203.0.113.10', CHROME_UA, '/puzzle/abc', headers, 10);
  assert.strictEqual(risk.components.no_accept_language, SCORE_WEIGHTS.no_accept_language);
});

test('locale path with non-overlapping Accept-Language is flagged', () => {
  const risk = computeRiskScore('203.0.113.10', CHROME_UA, '/ja/puzzles',
    coherentHeaders({ 'accept-language': 'en-US,en;q=0.9' }), 10);
  assert.strictEqual(risk.components.locale_lang_mismatch, SCORE_WEIGHTS.locale_lang_mismatch);
  // matching language does not fire
  const ok = computeRiskScore('203.0.113.10', CHROME_UA, '/ja/puzzles',
    coherentHeaders({ 'accept-language': 'ja,en;q=0.8' }), 10);
  assert.strictEqual(ok.components.locale_lang_mismatch, undefined);
});

test('cookieless claimed-internal navigation is the GA-pollution signature', () => {
  const headers = coherentHeaders({ 'sec-fetch-site': 'same-origin' });
  delete headers['cookie'];
  const risk = computeRiskScore('203.0.113.10', CHROME_UA, '/puzzle/abc', headers, 10);
  assert.strictEqual(risk.components.cookieless_same_origin, SCORE_WEIGHTS.cookieless_same_origin);
});

test('cookieless referer-less deep entry adds a weak signal', () => {
  const headers = coherentHeaders();
  delete headers['cookie'];
  const risk = computeRiskScore('203.0.113.10', CHROME_UA, '/en/players/abc', headers, 10);
  assert.strictEqual(risk.components.cookieless_deep_direct, SCORE_WEIGHTS.cookieless_deep_direct);
  // shallow entry (homepage) does not fire
  const shallow = computeRiskScore('203.0.113.10', CHROME_UA, '/', headers, 10);
  assert.strictEqual(shallow.components.cookieless_deep_direct, undefined);
});

// -----------------------------------------------------------------------------
// Pressure
// -----------------------------------------------------------------------------

test('pressure multiplies the base and unlocks the surge signal', () => {
  const headers = coherentHeaders({ 'accept-language': 'en-US,en;q=0.9' });
  delete headers['cookie'];
  // /ja/ + en-only AL + cookieless deep direct = 15 + 10 = 25 base at calm
  const calm = computeRiskScore('203.0.113.10', CHROME_UA, '/ja/puzzles/abc', headers, 300);
  assert.strictEqual(calm.base, 25);
  assert.strictEqual(calm.score, 25);
  // At 3× baseline: +surge_locale_cookieless 20 → base 45, ×2.5 (capped) = 113
  const surge = computeRiskScore('203.0.113.10', CHROME_UA, '/ja/puzzles/abc', headers, 900);
  assert.strictEqual(surge.components.surge_locale_cookieless, 20);
  assert.strictEqual(surge.base, 45);
  assert.strictEqual(surge.score, Math.round(45 * 2.5));
});

test('pressure below 1 never discounts the base score', () => {
  const headers = coherentHeaders({ 'sec-ch-ua-platform': '"Linux"' });
  const quiet = computeRiskScore('203.0.113.10', CHROME_UA, '/puzzle/abc', headers, 1);
  assert.strictEqual(quiet.score, SCORE_WEIGHTS.platform_mismatch);
});

// -----------------------------------------------------------------------------
// uaOsFamily
// -----------------------------------------------------------------------------

test('uaOsFamily maps the common UA families', () => {
  assert.strictEqual(uaOsFamily(CHROME_UA), 'Windows');
  assert.strictEqual(uaOsFamily(SAFARI_UA), 'iOS');
  assert.strictEqual(uaOsFamily('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/150.0.0.0'), 'Android');
  assert.strictEqual(uaOsFamily('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'), 'macOS');
  assert.strictEqual(uaOsFamily('Mozilla/5.0 (X11; Linux x86_64)'), 'Linux');
  assert.strictEqual(uaOsFamily('curl/8.7.1'), null);
});
