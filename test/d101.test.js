// lily.srv D101 (2026-11-16): the never-challenged residential swarm — stale
// desktop Chrome and a non-Czech browser language on unprefixed (Czech) deep
// URLs, both only for cookieless requests.
const { test } = require('node:test');
const assert = require('node:assert');

delete process.env.STALE_CHROME_MIN_MAJOR;
const bb = require('../server.js');

const mac = (v) => `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;
const H = (extra = {}) => ({
  'accept-language': 'en-US,en;q=0.9',
  'sec-fetch-site': 'none',
  'sec-ch-ua': '"Chromium";v="1"',
  'sec-ch-ua-platform': '"macOS"',
  ...extra,
});
const DAY = 24 * 3600 * 1000;

test('stale cutoff follows the 2-week cadence from Chrome 153 (2026-09-08), lag 9', () => {
  assert.strictEqual(bb.staleChromeCutoff(Date.UTC(2026, 8, 8)), 144);
  assert.strictEqual(bb.staleChromeCutoff(Date.UTC(2026, 10, 16)), 148);   // est. 157 = what logged-in users run
  assert.strictEqual(bb.staleChromeCutoff(Date.UTC(2026, 10, 16) + 28 * DAY), 150);
  process.env.STALE_CHROME_MIN_MAJOR = '140';
  assert.strictEqual(bb.staleChromeCutoff(), 140);
  delete process.env.STALE_CHROME_MIN_MAJOR;
});

test('the swarm profile scores stale_browser + default_locale_lang_mismatch on top of cookieless_deep_direct', () => {
  const r = bb.computeRiskScore('198.51.100.1', mac(136), '/vysledek/01a1943e-9e7d-7118-b8b6-8e016ce5dbfc', H(), 450);
  assert.deepStrictEqual(Object.keys(r.components).sort(),
    ['cookieless_deep_direct', 'default_locale_lang_mismatch', 'direct_entry', 'stale_browser']);
  assert.ok(r.score >= bb.SCORE_THRESHOLD, `score ${r.score}`);       // 40 x 1.5 = 60
});

test('a returning visitor (cookies) never gets the new components', () => {
  const r = bb.computeRiskScore('198.51.100.1', mac(136), '/vysledek/abc', H({ cookie: 'PHPSESSID=x' }), 750);
  assert.strictEqual(r.components.stale_browser, undefined);
  assert.strictEqual(r.components.default_locale_lang_mismatch, undefined);
});

test('a current Chrome foreigner on a shared Czech link: scored 50 without D105; D105 challenges the cookieless direct entry, a referer clears it', () => {
  const viaReferer = bb.computeRiskScore('198.51.100.1', mac(157), '/vysledek/abc',
    H({ 'sec-fetch-site': 'cross-site', referer: 'https://l.facebook.com/' }), 10000);
  assert.strictEqual(viaReferer.components.stale_browser, undefined);
  assert.ok(viaReferer.score < bb.SCORE_THRESHOLD, `score ${viaReferer.score}`);
  const typedIn = bb.computeRiskScore('198.51.100.1', mac(157), '/vysledek/abc', H(), 10000);
  assert.strictEqual(typedIn.floor, 'cookieless_direct_entry');
});

test('Czech / Slovak browsers, prefixed URLs and the home page never get default_locale_lang_mismatch', () => {
  for (const [path, al] of [['/vysledek/abc', 'cs-CZ,cs;q=0.9'], ['/vysledek/abc', 'sk'], ['/vysledek/abc', 'en-US,en;q=0.9,cs;q=0.8'],
    ['/en/result/abc', 'en-US'], ['/', 'en-US'], ['/feedback', 'en-US']]) {
    const r = bb.computeRiskScore('198.51.100.1', mac(157), path, H({ 'accept-language': al }), 0);
    assert.strictEqual(r.components.default_locale_lang_mismatch, undefined, `${path} ${al}`);
  }
});

test('mobile and lagging Chromium browsers are never stale', () => {
  for (const ua of [
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.0.0 Mobile/15E148 Safari/604.1',
  ]) {
    const r = bb.computeRiskScore('198.51.100.1', ua, '/en/puzzle/abc', H(), 0);
    assert.strictEqual(r.components.stale_browser, undefined, ua);
  }
  const win = bb.computeRiskScore('198.51.100.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    '/en/puzzle/abc', H({ 'sec-ch-ua-platform': '"Windows"' }), 0);
  assert.strictEqual(win.components.stale_browser, 20);
});

test('D102: Linux desktop on a cookieless direct deep link adds +10 — never enough alone', () => {
  const linux = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
  const h = H({ 'sec-ch-ua-platform': '"Linux"', 'sec-fetch-site': 'cross-site' });   // keep D105 out
  // English page, English browser, pressure 2.0 (no surge component): 20 x 2 = 40 -> not challenged
  const en = bb.computeRiskScore('198.51.100.1', linux, '/en/result/abc', h, 600);
  assert.strictEqual(en.components.linux_desktop_cookieless, 10);
  assert.ok(en.score < bb.SCORE_THRESHOLD, `score ${en.score}`);
  // the GA-loading swarm shape: Czech URL, en-US -> 30 x 2 = 60
  const cz = bb.computeRiskScore('198.51.100.1', linux, '/statistiky-hrace/abc', h, 600);
  assert.ok(cz.score >= bb.SCORE_THRESHOLD, `score ${cz.score}`);
  // with cookies, or a referer (not a direct deep entry): nothing
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', linux, '/statistiky-hrace/abc', H({ cookie: 'a=b' }), 0).components.linux_desktop_cookieless, undefined);
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', linux, '/statistiky-hrace/abc', H({ referer: 'https://myspeedpuzzling.com/' }), 0).components.linux_desktop_cookieless, undefined);
  // Android carries "Linux" but never "X11; Linux"
  const android = 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36';
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', android, '/statistiky-hrace/abc', H(), 0).components.linux_desktop_cookieless, undefined);
});

test('D103: stale desktop Chrome on a cookieless direct deep link is challenged at any pressure', () => {
  const r = bb.computeRiskScore('198.51.100.1', mac(136), '/en/result/abc', H({ 'accept-language': 'en-US' }), 0);
  assert.ok(r.components.stale_browser && r.components.cookieless_deep_direct);
  assert.strictEqual(r.score, bb.SCORE_THRESHOLD);
  assert.strictEqual(r.floor, 'stale_cookieless_direct');
  // no floor with a referer (not a direct entry) or with cookies, or for a current browser
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', mac(136), '/en/result/abc', H({ referer: 'https://www.google.com/' }), 0).floor, undefined);
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', mac(136), '/en/result/abc', H({ cookie: 'a=b' }), 0).floor, undefined);
  // a current browser is not stale (a typed-in entry is still caught by D105, so test a cross-site one)
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', mac(157), '/en/result/abc', H({ 'sec-fetch-site': 'cross-site' }), 0).floor, undefined);
});

test('D104: stale desktop Firefox counts as stale_browser; ESR, current and mobile Firefox do not', () => {
  const ff = (v, os = 'Macintosh; Intel Mac OS X 10.15') => `Mozilla/5.0 (${os}; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`;
  assert.strictEqual(bb.staleFirefoxCutoff(Date.UTC(2026, 10, 17)), 155);
  const h = { 'accept-language': 'en-US,en;q=0.5', 'sec-fetch-site': 'none' };
  const old = bb.computeRiskScore('198.51.100.1', ff(151), '/es/resultado/abc', h, 0);
  assert.strictEqual(old.components.stale_browser, 20);
  assert.strictEqual(old.floor, 'stale_cookieless_direct');
  for (const v of [160, 158, 140, 153]) {
    assert.strictEqual(bb.computeRiskScore('198.51.100.1', ff(v), '/es/resultado/abc', h, 0).components.stale_browser, undefined, `Firefox ${v}`);
  }
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', 'Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0', '/es/resultado/abc', h, 0).components.stale_browser, undefined);
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', ff(151, 'Windows NT 10.0; Win64; x64'), '/es/resultado/abc', h, 0).components.stale_browser, 20);
});

test('D105: a cookieless, referer-less direct entry onto a deep page is challenged at any pressure', () => {
  const ua = mac(157);
  const direct = bb.computeRiskScore('198.51.100.1', ua, '/en/result/abc', H({ 'sec-fetch-site': 'none' }), 0);
  assert.strictEqual(direct.components.direct_entry, 0);
  assert.strictEqual(direct.score, bb.SCORE_THRESHOLD);
  assert.strictEqual(direct.floor, 'cookieless_direct_entry');
  // not for: a cookie, a referer, an in-site navigation, the home page, a missing sec-fetch-site
  for (const [path, extra] of [
    ['/en/result/abc', { cookie: '_ga=GA1.1.1.1' }],
    ['/en/result/abc', { referer: 'https://www.google.com/' }],
    ['/en/result/abc', { 'sec-fetch-site': 'same-origin', referer: 'https://myspeedpuzzling.com/en' }],
    ['/en/result/abc', { 'sec-fetch-site': 'cross-site', referer: 'https://www.facebook.com/' }],
    ['/en', { 'sec-fetch-site': 'none' }],
  ]) {
    const r = bb.computeRiskScore('198.51.100.1', ua, path, H({ 'sec-fetch-site': 'none', ...extra }), 0);
    assert.strictEqual(r.floor, undefined, `${path} ${JSON.stringify(extra)}`);
  }
  const noHeader = { 'accept-language': 'en-US', 'sec-ch-ua': '"x"', 'sec-ch-ua-platform': '"macOS"' };
  assert.strictEqual(bb.computeRiskScore('198.51.100.1', ua, '/en/result/abc', noHeader, 0).floor, undefined);
});
