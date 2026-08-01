// Unit tests for the human-recovery challenge (Cloudflare Turnstile).
// Run with: npm test  (node --test)
//
// server.js is required with challenge env preset; the require.main guard
// keeps the server from starting and the log dir from being created.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';
process.env.CHALLENGE_COOKIE_TTL_DAYS = '7';

// Mock siteverify: /pass answers success, /fail answers failure, /slow hangs
// longer than the 5s client timeout would allow in real life (we use it only
// to prove the timeout path returns false, with a shorter hang).
let mockServer;
let mockPort;

before(async () => {
  mockServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      if (req.url === '/pass') {
        // Echo assertions: the middleware must send form-encoded secret+response
        const params = new URLSearchParams(body);
        const ok = params.get('secret') && params.get('response') && params.get('remoteip');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ success: !!ok }));
      } else if (req.url === '/fail') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ success: false, 'error-codes': ['invalid-input-response'] }));
      } else if (req.url === '/http500') {
        res.statusCode = 500;
        res.end('boom');
      } else {
        res.statusCode = 404;
        res.end();
      }
    });
  });
  await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
  mockPort = mockServer.address().port;
  process.env.TURNSTILE_VERIFY_URL = `http://127.0.0.1:${mockPort}/pass`;
});

after(() => new Promise((resolve) => mockServer.close(resolve)));

// Required AFTER env is set (config consts are read at module load).
// TURNSTILE_VERIFY_URL is read at load too, so set a placeholder now and
// point tests at specific paths via the exported function's closure — the
// const captures the /pass URL from the before() hook via lazy require below.
let serverModule;
function mod() {
  if (!serverModule) {
    serverModule = require('../server.js');
  }
  return serverModule;
}

// -----------------------------------------------------------------------------
// Pass cookie
// -----------------------------------------------------------------------------

test('challenge is enabled when all secrets are set', () => {
  assert.strictEqual(mod().CHALLENGE_ENABLED, true);
});

test('makePassCookie produces a cookie hasValidPassCookie accepts for the same IP', () => {
  const { makePassCookie, hasValidPassCookie, CHALLENGE_COOKIE_NAME } = mod();
  const setCookie = makePassCookie('203.0.113.7');
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Lax/);
  const value = setCookie.split(';')[0]; // "__bb_pass=..."
  assert.ok(value.startsWith(`${CHALLENGE_COOKIE_NAME}=`));
  assert.strictEqual(hasValidPassCookie(value, '203.0.113.7'), true);
});

test('pass cookie is IP-bound — another IP rejects it', () => {
  const { makePassCookie, hasValidPassCookie } = mod();
  const value = makePassCookie('203.0.113.7').split(';')[0];
  assert.strictEqual(hasValidPassCookie(value, '203.0.113.8'), false);
});

test('tampered signature rejects', () => {
  const { makePassCookie, hasValidPassCookie } = mod();
  const value = makePassCookie('203.0.113.7').split(';')[0];
  const tampered = value.slice(0, -2) + (value.endsWith('aa') ? 'bb' : 'aa');
  assert.strictEqual(hasValidPassCookie(tampered, '203.0.113.7'), false);
});

test('expired cookie rejects', () => {
  const { signPassCookie, hasValidPassCookie, CHALLENGE_COOKIE_NAME } = mod();
  const past = Date.now() - 1000;
  const value = `${CHALLENGE_COOKIE_NAME}=${past}.${signPassCookie('203.0.113.7', past)}`;
  assert.strictEqual(hasValidPassCookie(value, '203.0.113.7'), false);
});

test('forged expiry without re-signing rejects', () => {
  const { signPassCookie, hasValidPassCookie, CHALLENGE_COOKIE_NAME } = mod();
  const past = Date.now() - 1000;
  const future = Date.now() + 999999;
  // Signature made for `past`, expiry claims `future`
  const value = `${CHALLENGE_COOKIE_NAME}=${future}.${signPassCookie('203.0.113.7', past)}`;
  assert.strictEqual(hasValidPassCookie(value, '203.0.113.7'), false);
});

test('cookie is found among other cookies', () => {
  const { makePassCookie, hasValidPassCookie } = mod();
  const value = makePassCookie('203.0.113.7').split(';')[0];
  const header = `PHPSESSID=abc; ${value}; theme=dark`;
  assert.strictEqual(hasValidPassCookie(header, '203.0.113.7'), true);
});

test('absent/garbage cookie header rejects', () => {
  const { hasValidPassCookie } = mod();
  assert.strictEqual(hasValidPassCookie(undefined, '203.0.113.7'), false);
  assert.strictEqual(hasValidPassCookie('', '203.0.113.7'), false);
  assert.strictEqual(hasValidPassCookie('__bb_pass=nonsense', '203.0.113.7'), false);
  assert.strictEqual(hasValidPassCookie('__bb_pass=123456789', '203.0.113.7'), false);
});

// -----------------------------------------------------------------------------
// Token extraction
// -----------------------------------------------------------------------------

test('extractChallengeToken pulls the token and strips only that param', () => {
  const { extractChallengeToken } = mod();
  const result = extractChallengeToken('/en/puzzle?page=2&__bb_token=tok123&sort=name');
  assert.strictEqual(result.token, 'tok123');
  assert.strictEqual(result.cleanUri, '/en/puzzle?page=2&sort=name');
});

test('extractChallengeToken returns null without token', () => {
  const { extractChallengeToken } = mod();
  assert.strictEqual(extractChallengeToken('/en/puzzle?page=2'), null);
  assert.strictEqual(extractChallengeToken('/'), null);
});

test('extractChallengeToken handles token-only query', () => {
  const { extractChallengeToken } = mod();
  const result = extractChallengeToken('/de/feedback?__bb_token=abc');
  assert.strictEqual(result.token, 'abc');
  assert.strictEqual(result.cleanUri, '/de/feedback');
});

// -----------------------------------------------------------------------------
// siteverify
// -----------------------------------------------------------------------------

test('verifyTurnstileToken accepts a passing token', async () => {
  const { verifyTurnstileToken } = mod();
  assert.strictEqual(await verifyTurnstileToken('good-token', '203.0.113.7'), true);
});

test('verifyTurnstileToken fails closed on HTTP 500', async () => {
  // Re-require trick is not possible for the const URL — instead the mock
  // /pass endpoint validates required fields; garbage secret cannot happen
  // (const). Cover the rejection path via the /fail-shaped response by
  // swapping the mock handler temporarily.
  const { verifyTurnstileToken } = mod();
  const original = mockServer.listeners('request')[0];
  mockServer.removeAllListeners('request');
  mockServer.on('request', (req, res) => { res.statusCode = 500; res.end('boom'); });
  try {
    assert.strictEqual(await verifyTurnstileToken('any', '203.0.113.7'), false);
  } finally {
    mockServer.removeAllListeners('request');
    mockServer.on('request', original);
  }
});

test('verifyTurnstileToken fails closed when siteverify says no', async () => {
  const { verifyTurnstileToken } = mod();
  const original = mockServer.listeners('request')[0];
  mockServer.removeAllListeners('request');
  mockServer.on('request', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: false, 'error-codes': ['timeout-or-duplicate'] }));
  });
  try {
    assert.strictEqual(await verifyTurnstileToken('replayed', '203.0.113.7'), false);
  } finally {
    mockServer.removeAllListeners('request');
    mockServer.on('request', original);
  }
});

test('verifyTurnstileToken fails closed on connection refused', async () => {
  const { verifyTurnstileToken } = mod();
  // Point nothing at this port — the const URL targets the live mock, so
  // simulate by closing and reopening after. Simpler: a second module load is
  // impossible; instead hit the mock with a path that 404s (non-ok response).
  const original = mockServer.listeners('request')[0];
  mockServer.removeAllListeners('request');
  mockServer.on('request', (req, res) => { req.destroy(); });
  try {
    assert.strictEqual(await verifyTurnstileToken('any', '203.0.113.7'), false);
  } finally {
    mockServer.removeAllListeners('request');
    mockServer.on('request', original);
  }
});

// -----------------------------------------------------------------------------
// Verify-attempt rate limiting
// -----------------------------------------------------------------------------

test('verify attempts rate-limit per IP', () => {
  const { isVerifyRateLimited } = mod();
  const ip = '198.51.100.42';
  for (let i = 0; i < 5; i++) {
    assert.strictEqual(isVerifyRateLimited(ip), false, `attempt ${i + 1} should pass`);
  }
  assert.strictEqual(isVerifyRateLimited(ip), true, 'attempt 6 should be limited');
  // Different IP unaffected
  assert.strictEqual(isVerifyRateLimited('198.51.100.43'), false);
});

// -----------------------------------------------------------------------------
// Rule flags
// -----------------------------------------------------------------------------

test('only UA-signature rules are challenge-eligible, named bots are not', () => {
  const { BLOCKED_BOTS } = mod();
  const eligible = BLOCKED_BOTS.filter(b => b.challenge);
  const hard = BLOCKED_BOTS.filter(b => !b.challenge);

  // Every eligible rule is a signature/impossible-combo rule
  for (const rule of eligible) {
    assert.match(rule.reason, /Impossible|Fake|Dead device/i,
      `unexpected challenge-eligible rule: ${rule.reason}`);
  }

  // Self-identified bots and headless automation must stay hard
  const mustStayHard = ['GPTBot', 'ClaudeBot', 'HeadlessChrome', 'SpiderLing', 'ChatGPT-User'];
  for (const name of mustStayHard) {
    const rule = BLOCKED_BOTS.find(b => b.pattern.source.includes(name));
    assert.ok(rule, `rule for ${name} exists`);
    assert.ok(!rule.challenge, `${name} must not be challenge-eligible`);
  }

  // The three flagship recoverable signatures are flagged
  assert.ok(eligible.some(b => b.reason.includes('Dead device')), 'dead device is eligible');
  assert.ok(eligible.some(b => b.reason.includes('Presto')), 'Presto is eligible');
  assert.ok(eligible.some(b => b.reason.includes('Windows Vista')), 'impossible combos are eligible');
});

// -----------------------------------------------------------------------------
// Redirect absolutization (Traefik resolves relative Location against the
// AUTH SERVER url — production bug found 2026-08-01)
// -----------------------------------------------------------------------------

test('buildRedirectUrl absolutizes with forwarded proto+host', () => {
  const { buildRedirectUrl } = mod();
  const headers = { 'x-forwarded-host': 'myspeedpuzzling.com', 'x-forwarded-proto': 'https' };
  assert.strictEqual(buildRedirectUrl(headers, '/en/puzzle?page=2'), 'https://myspeedpuzzling.com/en/puzzle?page=2');
});

test('buildRedirectUrl defaults proto to https', () => {
  const { buildRedirectUrl } = mod();
  assert.strictEqual(buildRedirectUrl({ 'x-forwarded-host': 'myspeedpuzzling.com' }, '/'), 'https://myspeedpuzzling.com/');
});

test('buildRedirectUrl falls back to relative without forwarded host', () => {
  const { buildRedirectUrl } = mod();
  assert.strictEqual(buildRedirectUrl({}, '/en/puzzle'), '/en/puzzle');
});
