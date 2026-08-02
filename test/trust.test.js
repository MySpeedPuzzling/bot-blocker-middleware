// Unit tests for the trusted-human cookie (__bb_trust) — issued by the
// MySpeedPuzzling app, only VALIDATED here. Includes the cross-language
// GOLDEN VECTOR: the PHP signer's test asserts the exact same cookie string
// (tests/EventSubscriber/BotTrustCookieSubscriberTest.php in the app repo).
// If either side changes the wire format, its golden test breaks first.

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

process.env.TURNSTILE_SITE_KEY = '1x00000000000000000000AA';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
process.env.CHALLENGE_COOKIE_SECRET = 'test-secret-for-unit-tests';

const { getTrustedUid, TRUST_COOKIE_NAME } = require('../server.js');

const SECRET = 'test-secret-for-unit-tests';

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function buildTrustCookie(uid, iatMs, secret = SECRET) {
  const payload = Buffer.from(`bb-trust|v1|${uid}|${iatMs}`, 'utf8');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest();
  return `${b64url(payload)}.${b64url(sig)}`;
}

// -----------------------------------------------------------------------------
// Golden vector — MUST match the PHP signer byte-for-byte
// -----------------------------------------------------------------------------

const GOLDEN_UID = 'a1b2c3d4e5f60718';
const GOLDEN_IAT = 1754000000000;
const GOLDEN_COOKIE = 'YmItdHJ1c3R8djF8YTFiMmMzZDRlNWY2MDcxOHwxNzU0MDAwMDAwMDAw.'
  + '1RPyyufdp2q0_zj8wCHUH-pO3441xsojxNs65nh97sQ';

test('golden vector: signing algorithm matches the frozen cross-language constant', () => {
  assert.strictEqual(buildTrustCookie(GOLDEN_UID, GOLDEN_IAT), GOLDEN_COOKIE);
});

test('golden vector cookie is EXPIRED by now (iat 2025-08) and must be rejected', () => {
  assert.strictEqual(getTrustedUid(`${TRUST_COOKIE_NAME}=${GOLDEN_COOKIE}`), null);
});

// -----------------------------------------------------------------------------
// Validation behavior
// -----------------------------------------------------------------------------

test('fresh valid cookie returns the uid', () => {
  const cookie = buildTrustCookie('user-123', Date.now());
  assert.strictEqual(getTrustedUid(`${TRUST_COOKIE_NAME}=${cookie}`), 'user-123');
});

test('cookie is found among other cookies', () => {
  const cookie = buildTrustCookie('user-456', Date.now());
  const header = `PHPSESSID=abc; ${TRUST_COOKIE_NAME}=${cookie}; __bb_pass=zzz.yyy`;
  assert.strictEqual(getTrustedUid(header), 'user-456');
});

test('wrong secret is rejected', () => {
  const cookie = buildTrustCookie('user-123', Date.now(), 'some-other-secret');
  assert.strictEqual(getTrustedUid(`${TRUST_COOKIE_NAME}=${cookie}`), null);
});

test('tampered payload is rejected (uid swapped, signature kept)', () => {
  const good = buildTrustCookie('user-123', Date.now());
  const sig = good.split('.')[1];
  const forgedPayload = b64url(Buffer.from(`bb-trust|v1|admin|${Date.now()}`, 'utf8'));
  assert.strictEqual(getTrustedUid(`${TRUST_COOKIE_NAME}=${forgedPayload}.${sig}`), null);
});

test('a __bb_pass-style value in the trust cookie slot is rejected (domain separation)', () => {
  // Same secret signs both cookie types; the "bb-trust|v1|" payload prefix is
  // what keeps them from being interchangeable.
  const expires = Date.now() + 60000;
  const passStyle = crypto.createHmac('sha256', SECRET).update(`203.0.113.7|${expires}`).digest('hex');
  assert.strictEqual(getTrustedUid(`${TRUST_COOKIE_NAME}=${expires}.${passStyle}`), null);
});

test('malformed values are rejected without throwing', () => {
  for (const raw of ['', 'no-dot', '..', 'a.b', '!!!.###', `${b64url(Buffer.from('bb-trust|v1'))}.AAAA`]) {
    assert.strictEqual(getTrustedUid(`${TRUST_COOKIE_NAME}=${raw}`), null, `raw=${raw}`);
  }
  assert.strictEqual(getTrustedUid(undefined), null);
  assert.strictEqual(getTrustedUid('other=1'), null);
});

test('empty uid is rejected', () => {
  const cookie = buildTrustCookie('', Date.now());
  assert.strictEqual(getTrustedUid(`${TRUST_COOKIE_NAME}=${cookie}`), null);
});
