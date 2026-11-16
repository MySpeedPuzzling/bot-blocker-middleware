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
    ['cookieless_deep_direct', 'default_locale_lang_mismatch', 'stale_browser']);
  assert.ok(r.score >= bb.SCORE_THRESHOLD, `score ${r.score}`);       // 40 x 1.5 = 60
});

test('a returning visitor (cookies) never gets the new components', () => {
  const r = bb.computeRiskScore('198.51.100.1', mac(136), '/vysledek/abc', H({ cookie: 'PHPSESSID=x' }), 750);
  assert.strictEqual(r.components.stale_browser, undefined);
  assert.strictEqual(r.components.default_locale_lang_mismatch, undefined);
});

test('a current Chrome foreigner opening a shared Czech link is not challenged even at max pressure', () => {
  const r = bb.computeRiskScore('198.51.100.1', mac(157), '/vysledek/abc', H(), 10000);
  assert.strictEqual(r.components.stale_browser, undefined);
  assert.ok(r.score < bb.SCORE_THRESHOLD, `score ${r.score}`);       // (10+10) x 2.5 = 50
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
  const h = H({ 'sec-ch-ua-platform': '"Linux"' });
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
