// Unit tests for the visitor-facing pages (D50 rebrand): locale selection,
// per-kind content, the untouched challenge mechanics, and escaping.
//
// These pages are the ONLY thing a wrongly-blocked human ever sees, so the
// tests assert the things that would silently ruin them: a missing widget
// callback (challenge can never be solved), a leaked raw reason string, or a
// page rendering in the wrong language.

const { test } = require('node:test');
const assert = require('node:assert');

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';
process.env.CONTACT_EMAIL = 'jan@myspeedpuzzling.com';

const { renderPage, detectPageLocale, PAGE_STRINGS } = require('../server.js');

// -----------------------------------------------------------------------------
// Locale selection
// -----------------------------------------------------------------------------

test('locale comes from the URL prefix first', () => {
  assert.strictEqual(detectPageLocale('/cs/skladam-puzzle/abc', 'en-US,en;q=0.9'), 'cs');
  assert.strictEqual(detectPageLocale('/ja/', 'de-DE'), 'ja');
  assert.strictEqual(detectPageLocale('/en/puzzles', 'cs-CZ'), 'en');
});

test('Accept-Language is the fallback for unprefixed paths', () => {
  assert.strictEqual(detectPageLocale('/puzzle/abc', 'cs-CZ,cs;q=0.9,en;q=0.8'), 'cs');
  assert.strictEqual(detectPageLocale('/puzzle/abc', 'de-DE,de;q=0.9'), 'de');
  assert.strictEqual(detectPageLocale('/puzzle/abc', 'en-GB,en'), 'en');
});

test('unknown locales and junk fall back to English', () => {
  assert.strictEqual(detectPageLocale('/pl/puzzle', 'pl-PL'), 'en');
  assert.strictEqual(detectPageLocale('/', ''), 'en');
  assert.strictEqual(detectPageLocale('', undefined), 'en');
});

test('every locale defines every string the renderer uses', () => {
  const keys = Object.keys(PAGE_STRINGS.en);
  for (const [locale, strings] of Object.entries(PAGE_STRINGS)) {
    for (const key of keys) {
      assert.ok(strings[key], `${locale} is missing ${key}`);
    }
  }
});

// -----------------------------------------------------------------------------
// Challenge mechanics — the parts that must never change with a restyle
// -----------------------------------------------------------------------------

test('challenge page keeps widget, sitekey, callback and verify script', () => {
  const html = renderPage('challenge', { reason: 'Risk score 113', locale: 'en', ip: '203.0.113.7' });
  assert.match(html, /class="cf-turnstile"/);
  assert.match(html, /data-sitekey="1x00000000000000000000AA"/);
  assert.match(html, /data-callback="__bbSolved"/);
  assert.match(html, /function __bbSolved\(token\)/);
  assert.match(html, /searchParams\.set\('__bb_token', token\)/);
  assert.match(html, /challenges\.cloudflare\.com\/turnstile\/v0\/api\.js/);
});

test('non-challenge pages carry no widget and no Turnstile script', () => {
  for (const kind of ['ratelimit', 'blocked']) {
    const html = renderPage(kind, { reason: 'x', locale: 'en', ip: '203.0.113.7' });
    assert.doesNotMatch(html, /cf-turnstile/, kind);
    assert.doesNotMatch(html, /challenges\.cloudflare\.com/, kind);
    assert.doesNotMatch(html, /__bbSolved/, kind);
  }
});

// -----------------------------------------------------------------------------
// Content
// -----------------------------------------------------------------------------

test('page renders in the requested language with the right heading', () => {
  const cs = renderPage('challenge', { locale: 'cs' });
  assert.match(cs, /<html lang="cs">/);
  assert.ok(cs.includes(PAGE_STRINGS.cs.challengeTitle));
  const ja = renderPage('blocked', { locale: 'ja' });
  assert.match(ja, /<html lang="ja">/);
  assert.ok(ja.includes(PAGE_STRINGS.ja.blockedTitle));
});

test('technical details carry the reason AND the client IP, labelled per locale', () => {
  const html = renderPage('blocked', { reason: 'Known Chinese botnet subnet', locale: 'cs', ip: '198.51.100.9' });
  assert.ok(html.includes('198.51.100.9'), 'IP shown for support mails');
  assert.ok(html.includes('Known Chinese botnet subnet'));
  assert.ok(html.includes(PAGE_STRINGS.cs.labelIp));
  assert.ok(html.includes(PAGE_STRINGS.cs.labelReason));
});

test('the details block is omitted when there is nothing to show', () => {
  assert.doesNotMatch(renderPage('ratelimit', { locale: 'en' }), /<details>/);
  // ...but appears as soon as we know the IP, even with no reason
  assert.match(renderPage('ratelimit', { locale: 'en', ip: '203.0.113.7' }), /<details>/);
});

test('brand assets are same-origin and degrade safely', () => {
  const html = renderPage('challenge', { locale: 'en' });
  assert.match(html, /src="\/img\/speedpuzzling-logo\.svg"/);
  assert.match(html, /onerror="this\.style\.display='none'"/);
  assert.match(html, /url\(\/fonts\/rubik\/rubik-latin\.woff2\)/);
  // No third-party origin other than the Turnstile widget itself
  const externals = html.match(/https?:\/\/[^"' )]+/g) || [];
  for (const url of externals) {
    assert.ok(url.startsWith('https://challenges.cloudflare.com'), `unexpected external ${url}`);
  }
});

test('pages are noindex and carry the contact address', () => {
  const html = renderPage('blocked', { locale: 'en', ip: '1.2.3.4' });
  assert.match(html, /name="robots" content="noindex, nofollow"/);
  assert.ok(html.includes('jan@myspeedpuzzling.com'));
});

// -----------------------------------------------------------------------------
// Escaping — a block page must never become an injection surface
// -----------------------------------------------------------------------------

test('reason and IP are HTML-escaped', () => {
  const html = renderPage('blocked', {
    reason: '<script>alert(1)</script>',
    ip: '"><img src=x onerror=alert(1)>',
    locale: 'en',
  });
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.ok(html.includes('&lt;script&gt;'));
});

// -----------------------------------------------------------------------------
// Challenge page: logged-in users are never challenged — the page says so and
// links to /login (D96 follow-up). The login pages themselves are exempt from
// the risk ladder so that link never leads into a second challenge.
// -----------------------------------------------------------------------------

test('challenge page tells visitors that logged-in puzzlers skip the check, in every locale', () => {
  const { renderPage, PAGE_STRINGS } = require('../server.js');
  for (const locale of Object.keys(PAGE_STRINGS)) {
    const html = renderPage('challenge', { locale });
    assert.ok(PAGE_STRINGS[locale].challengeLoginHint, `${locale} has a login hint`);
    assert.ok(html.includes(PAGE_STRINGS[locale].challengeLoginHint), `${locale} renders it`);
    assert.match(html, /<a id="bb-login" href="\/login">/);
    assert.match(html, /\/login\?return=/, 'script points the link back at the wanted page');
  }
  // Only the challenge page carries it.
  assert.ok(!renderPage('blocked', { locale: 'en' }).includes('bb-login'));
  assert.ok(!renderPage('ratelimit', { locale: 'en' }).includes('bb-login'));
});

test('sign-in, registration, magic-link and social-login pages are exempt from the risk ladder', () => {
  const { isScoringExemptPath } = require('../server.js');
  for (const p of ['/login', '/en/login', '/de/login/', '/register', '/es/register', '/register/social',
    '/en/login-link', '/login-link/sent', '/login/social/google', '/en/login/social/apple/callback?code=x']) {
    assert.strictEqual(isScoringExemptPath(p), true, p);
  }
  for (const p of ['/en/loginx', '/en/result/login', '/en/puzzle/register', '/en/registration-stats', '/xx/login']) {
    assert.strictEqual(isScoringExemptPath(p), false, p);
  }
});
