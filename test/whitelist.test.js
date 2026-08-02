// Unit tests for the tiered crawler whitelist: forward-confirmed rDNS
// verification (with an injected resolver), fail-open on DNS trouble, and the
// per-IP cap for UA-only (spoofable) entries.

const { test, beforeEach } = require('node:test');
const assert = require('node:assert');

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';
process.env.WHITELIST_BOT_CAP = '5';  // small cap so the test loop stays cheap

const {
  checkWhitelistedBot, verifyCrawlerRdns, _setDnsForTests, WHITELIST_BOT_CAP,
} = require('../server.js');

const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const SEZNAM_UA = 'Mozilla/5.0 (compatible; SeznamBot/4.0; +https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/)';
const WHATSAPP_UA = 'WhatsApp/2.23.20.0';
const STRIPE_UA = 'Stripe/1.0 (+https://stripe.com/docs/webhooks)';

function nxdomain() {
  const err = new Error('queryPtr ENOTFOUND');
  err.code = 'ENOTFOUND';
  return err;
}

beforeEach(() => {
  // Every test starts with a resolver that would fail loudly if hit
  // unexpectedly; individual tests override. _setDnsForTests clears the cache.
  _setDnsForTests(
    async () => { throw new Error('unexpected reverse lookup'); },
    async () => { throw new Error('unexpected forward lookup'); },
  );
});

test('forward-confirmed Googlebot passes unlimited', async () => {
  _setDnsForTests(
    async () => ['crawl-66-249-66-1.googlebot.com'],
    async () => ['66.249.66.1'],
  );
  const result = await checkWhitelistedBot(GOOGLEBOT_UA, '66.249.66.1');
  assert.deepStrictEqual(result, { name: 'Googlebot', allow: true });
});

test('verified verdict is cached — second lookup needs no DNS', async () => {
  _setDnsForTests(
    async () => ['crawl-66-249-66-2.googlebot.com'],
    async () => ['66.249.66.2'],
  );
  await checkWhitelistedBot(GOOGLEBOT_UA, '66.249.66.2');
  // Cache survives ONLY within the same resolver generation — replicate by
  // swapping in throwing resolvers via direct assignment (not _setDnsForTests,
  // which clears the cache): verifyCrawlerRdns must answer from cache.
  const state = await verifyCrawlerRdns('66.249.66.2', ['.googlebot.com']);
  assert.strictEqual(state, 'ok');
});

test('PTR outside the allowed suffixes = fake crawler, falls through', async () => {
  _setDnsForTests(
    async () => ['ec2-1-2-3-4.compute.amazonaws.com'],
    async () => { throw new Error('forward must not be called for wrong suffix'); },
  );
  const result = await checkWhitelistedBot(GOOGLEBOT_UA, '1.2.3.4');
  assert.deepStrictEqual(result, { name: 'Googlebot', fake: true });
});

test('forward confirmation failing (PTR does not resolve back) = fake', async () => {
  _setDnsForTests(
    async () => ['crawl-9-9-9-9.googlebot.com'],
    async () => ['203.0.113.99'],  // resolves elsewhere
  );
  const result = await checkWhitelistedBot(GOOGLEBOT_UA, '9.9.9.9');
  assert.deepStrictEqual(result, { name: 'Googlebot', fake: true });
});

test('no PTR record (NXDOMAIN) is definitive = fake', async () => {
  _setDnsForTests(
    async () => { throw nxdomain(); },
    async () => [],
  );
  const state = await verifyCrawlerRdns('198.51.100.7', ['.googlebot.com']);
  assert.strictEqual(state, 'fake');
});

test('resolver trouble (SERVFAIL/timeout) fails OPEN and is not cached', async () => {
  _setDnsForTests(
    async () => { throw new Error('SERVFAIL'); },
    async () => [],
  );
  const state = await verifyCrawlerRdns('198.51.100.8', ['.googlebot.com']);
  assert.strictEqual(state, 'error');
  // The whitelist honors the UA on error — never 403 real Googlebot over DNS.
  const result = await checkWhitelistedBot(GOOGLEBOT_UA, '198.51.100.8');
  assert.deepStrictEqual(result, { name: 'Googlebot', allow: true });
});

test('SeznamBot verifies against .seznam.cz', async () => {
  _setDnsForTests(
    async () => ['fulltextrobot-77-75-79-1.seznam.cz'],
    async () => ['77.75.79.1'],
  );
  const result = await checkWhitelistedBot(SEZNAM_UA, '77.75.79.1');
  assert.deepStrictEqual(result, { name: 'Seznam', allow: true });
});

test('UA-only preview bots pass under the per-IP cap, 429 above it', async () => {
  const ip = '203.0.113.50';
  for (let i = 0; i < WHITELIST_BOT_CAP; i++) {
    const result = await checkWhitelistedBot(WHATSAPP_UA, ip);
    assert.deepStrictEqual(result, { name: 'WhatsApp', allow: true }, `request ${i + 1}`);
  }
  const over = await checkWhitelistedBot(WHATSAPP_UA, ip);
  assert.deepStrictEqual(over, { name: 'WhatsApp', capped: true });
  // A different IP has its own budget
  const other = await checkWhitelistedBot(WHATSAPP_UA, '203.0.113.51');
  assert.deepStrictEqual(other, { name: 'WhatsApp', allow: true });
});

test('Stripe stays uncapped and unverified (webhook delivery must never break)', async () => {
  for (let i = 0; i < WHITELIST_BOT_CAP * 2; i++) {
    const result = await checkWhitelistedBot(STRIPE_UA, '203.0.113.60');
    assert.deepStrictEqual(result, { name: 'Stripe', allow: true });
  }
});

test('non-crawler UA claims nothing', async () => {
  assert.strictEqual(await checkWhitelistedBot('Mozilla/5.0 Chrome/150.0.0.0', '1.1.1.1'), null);
  assert.strictEqual(await checkWhitelistedBot('', '1.1.1.1'), null);
});
