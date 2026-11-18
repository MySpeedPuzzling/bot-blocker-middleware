const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns');
const net = require('net');
const readline = require('readline');

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONTACT_EMAIL = process.env.CONTACT_EMAIL || 'j.mikes@me.com';
const LOG_DIR = process.env.LOG_DIR || '/var/log/bot-blocker';
// Days of `blocked-*.log` to keep. The sidecar writes one JSON line per decision
// (50-170 MB a day under a swarm) and never used to prune: the volume reached
// 5.5 GB / 119 files by 2026-11-15. The daily `summary-*.txt` files are ~2 KB
// and ARE the long-term history, so they are never removed. 0 = keep everything.
const LOG_RETENTION_DAYS = (() => {
  const n = parseInt(process.env.LOG_RETENTION_DAYS, 10);
  return Number.isFinite(n) && n >= 0 ? n : 14;
})();
// Docker HEALTHCHECK target. Answered only on a DIRECT request: Traefik's
// forwardAuth always calls `/` and carries the visitor's path in
// X-Forwarded-Uri, so a visitor can neither reach nor spoof this through the edge.
const HEALTH_PATH = '/-/healthz';
const PORT = process.env.PORT || 3000;
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT, 10) || 45;
const RATE_WINDOW = parseInt(process.env.RATE_WINDOW, 10) || 60 * 1000; // 1 minute

// Human-recovery challenge (Cloudflare Turnstile).
// Heuristic rules that could plausibly catch a real human (UA-based signatures,
// the 43/8 combo, permabans) serve a challenge page instead of a flat 403.
// Solving it sets an HMAC-signed, IP-bound pass cookie and — if the IP was
// permabanned — lifts the ban. Behavioral rules (rate limit, scrape strikes)
// are NEVER bypassed by the cookie: a challenge proves a human is present,
// not that the traffic volume is acceptable.
// The challenge auto-disables (identical behavior to before) unless all three
// secrets are configured, so deploying without env changes is a no-op.
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';
// Overridable for tests (points at a local mock siteverify).
const TURNSTILE_VERIFY_URL = process.env.TURNSTILE_VERIFY_URL || 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const CHALLENGE_COOKIE_SECRET = process.env.CHALLENGE_COOKIE_SECRET || '';
const CHALLENGE_COOKIE_NAME = '__bb_pass';
const CHALLENGE_TOKEN_PARAM = '__bb_token';
// Pass lifetime. 24 h since 2026-11-16 (lily.srv D96) — it was 7 days, and a
// pass skips the whole risk ladder, so one paid Turnstile solve bought a
// week-long crawl licence for that exit IP. CHALLENGE_COOKIE_TTL_HOURS wins;
// the old CHALLENGE_COOKIE_TTL_DAYS is still honored when set.
const CHALLENGE_COOKIE_TTL_MS = (() => {
  const hours = parseInt(process.env.CHALLENGE_COOKIE_TTL_HOURS, 10);
  if (Number.isFinite(hours) && hours > 0) return hours * 3600 * 1000;
  const days = parseInt(process.env.CHALLENGE_COOKIE_TTL_DAYS, 10);
  if (Number.isFinite(days) && days > 0) return days * 24 * 3600 * 1000;
  return 24 * 3600 * 1000;
})();
// Hosting-class exits (datacenter/ISP-proxy ASN or curated cloud CIDR) get a
// SHORT pass and a SMALL page budget: during the 2026-11-13..15 wave
// DigitalOcean IPs solved the challenge ~94% of the time and ISP-proxy pools
// ~50-70% (humans: ~1-2%). A solve now buys an hour / a few dozen pages, not a week.
// Positive integer env, else the default (a negative TTL would mint passes
// that are expired on arrival; 0/garbage falls back too).
function positiveIntEnv(name, fallback) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}
const HOSTING_PASS_TTL_MS = positiveIntEnv('HOSTING_PASS_TTL_MIN', 60) * 60 * 1000;
// Scorable requests (anonymous HTML-accepting GETs — page loads, but also lazy
// turbo-frames and `Accept: */*` fetches, so ~3 per page view) one pass covers
// before the ladder looks again. Generous for residential visitors; tight for
// hosting exits (60 ≈ 20 page views), whose over-budget requests add
// `pass_exhausted`. A residential pass past budget is simply scored again.
const PASS_PAGE_BUDGET = positiveIntEnv('PASS_PAGE_BUDGET', 300);
const HOSTING_PASS_PAGE_BUDGET = positiveIntEnv('HOSTING_PASS_PAGE_BUDGET', 60);
// A pass whose remaining life exceeds its class TTL by more than this was
// minted under older/looser rules (the 7-day passes, or a residential pass
// presented from what is now a hosting IP) and is not honored.
const PASS_TTL_SLACK_MS = 60 * 1000;
const CHALLENGE_VERIFY_LIMIT = parseInt(process.env.CHALLENGE_VERIFY_LIMIT, 10) || 5; // siteverify attempts per IP per minute
const CHALLENGE_ENABLED = process.env.CHALLENGE_ENABLED !== 'false'
  && TURNSTILE_SITE_KEY !== '' && TURNSTILE_SECRET_KEY !== '' && CHALLENGE_COOKIE_SECRET !== '';

// Trusted-human cookie (__bb_trust), ISSUED BY THE APP on authenticated
// responses (BotTrustCookieSubscriber in the MySpeedPuzzling repo) and only
// VALIDATED here. A logged-in account is the strongest human signal we have:
// a valid cookie bypasses every heuristic in this middleware. Deliberately
// NOT IP-bound (unlike __bb_pass) — phones roam networks daily and puzzle
// competitions put 1000+ users behind one WiFi IP; the cookie must survive
// both. The HMAC input is domain-separated ("bb-trust|v1|...") from the pass
// cookie's ("<ip>|<expires>"), so both cookie types safely share
// CHALLENGE_COOKIE_SECRET — which the app already receives via its .env.
// Wire format (must match the app's signer byte-for-byte):
//   base64url("bb-trust|v1|<uid>|<iatMs>") + "." + base64url(HMAC-SHA256 raw)
const TRUST_COOKIE_NAME = '__bb_trust';
const TRUST_COOKIE_SECRET = process.env.TRUST_COOKIE_SECRET || CHALLENGE_COOKIE_SECRET;
const TRUST_COOKIE_TTL_MS = (parseInt(process.env.TRUST_COOKIE_TTL_DAYS, 10) || 365) * 24 * 60 * 60 * 1000;
const TRUST_ENABLED = TRUST_COOKIE_SECRET !== '';

// Risk-scoring ladder (see RISK SCORING section). 'off' | 'log' | 'challenge':
// 'log' (shadow mode, the default) computes and logs scores but never acts —
// deploying this is a no-op for traffic; flip to 'challenge' only after the
// shadow logs confirm the threshold is clean on real users.
const SCORING_MODE = (process.env.SCORING_MODE || 'log').toLowerCase();
const SCORE_THRESHOLD = parseInt(process.env.SCORE_THRESHOLD, 10) || 60;
// Scores >= this are logged (type risk_observe) even below the threshold, so
// the shadow phase sees the full distribution without logging every request.
const SCORE_LOG_MIN = parseInt(process.env.SCORE_LOG_MIN, 10) || 25;
// Countries with ~no genuine audience but dominant botnet exits (GA data).
const HIGH_RISK_COUNTRIES = new Set((process.env.HIGH_RISK_COUNTRIES || 'CN,HK,SG,VN,ID')
  .split(',').map(s => s.trim().toUpperCase()).filter(Boolean));
// Calm-traffic rate of scorable (anonymous HTML GET) requests per 5 minutes.
// Pressure = current rate / baseline; it multiplies scores (capped) so the
// ladder auto-tightens under a distributed crawl and relaxes when it stops.
const SURGE_BASELINE_5M = parseInt(process.env.SURGE_BASELINE_5M, 10) || 300;
// Extra base score for locale-prefixed cookieless requests while pressure > 2×
// — the exact surface the 2026-07 residential swarm crawled.
const SURGE_EXTRA_SCORE = parseInt(process.env.SURGE_EXTRA_SCORE, 10) || 20;
// Per-IP requests/min cap for whitelisted-by-UA-only crawlers (link-preview
// bots, DuckDuckBot): UA strings are trivially spoofable, so the uncapped
// whitelist is reserved for rDNS-verified crawlers.
const WHITELIST_BOT_CAP = parseInt(process.env.WHITELIST_BOT_CAP, 10) || 30;

// --- Hardening against deliberately forced fail-open (D98) -------------------
// The gate in front (D97) answers 200 when we are down or slow, so crashing or
// stalling this process is a bypass. UA length bounds regex time and Map key
// size; every per-key Map is capped (oldest insertion evicted — Maps iterate
// in insertion order, so this is O(1)).
const MAX_UA_LENGTH = positiveIntEnv('MAX_UA_LENGTH', 512);
const MAX_MAP_ENTRIES = positiveIntEnv('MAX_MAP_ENTRIES', 200000);

function capMap(map, max) {
  while (map.size > max) {
    map.delete(map.keys().next().value);
  }
}

// --- Log-only telemetry for the D98 rules that touch crawlers or traffic that
// cannot solve a challenge. Every would-be decision is logged (not sampled),
// once per rule+IP per WOULD_DEDUP_MS, as `would_cap` / `would_deny` /
// `would_score` with extra.rule.
const WOULD_DEDUP_MS = 10 * 60 * 1000;
const wouldSeen = new Map();  // "rule|ip" -> ts

function logWould(type, rule, ip, userAgent, requestPath, extra = {}) {
  const key = rule + '|' + ip;
  const now = Date.now();
  const seen = wouldSeen.get(key);
  if (seen && now - seen < WOULD_DEDUP_MS) return;
  wouldSeen.set(key, now);
  capMap(wouldSeen, MAX_MAP_ENTRIES);
  logBlocked(type, ip, userAgent, `${rule}`, (requestPath || '').split('?')[0], { rule, ...extra });
}

function slash24(ip) {
  if (!ip) return '';
  if (ip.includes(':')) return ip.split(':').slice(0, 3).join(':') + '::/48';
  return ip.split('.').slice(0, 3).join('.') + '.0/24';
}

// Spread of UA-only crawler names (Slurp, Qwant, link previews...) across /24s
// per hour — a fleet borrowing "Slurp" shows up as a sudden spread. Logged
// hourly as `crawler_spread`; alert-only, no limit (D98).
const uaOnlySpread = new Map();  // name -> Set(/24)

function recordUaOnlySpread(name, ip) {
  let set = uaOnlySpread.get(name);
  if (!set) {
    set = new Set();
    uaOnlySpread.set(name, set);
  }
  if (set.size < 50000) set.add(slash24(ip));
}

// Trust-cookie fan-out: distinct /24s per uid per hour. One account seen from
// many networks is a shared scraper credential. Log-only for now (D98): no
// uid was ever logged, so the threshold is set from this data, not guessed.
const TRUST_FANOUT_LOG = positiveIntEnv('TRUST_FANOUT_LOG', 10);
const trustFanout = new Map();  // uid -> Set(/24)

function recordTrustFanout(uid, ip, userAgent, requestPath) {
  let set = trustFanout.get(uid);
  if (!set) {
    set = new Set();
    trustFanout.set(uid, set);
    capMap(trustFanout, MAX_MAP_ENTRIES);
  }
  if (set.size > 1000) return;
  const before = set.size;
  set.add(slash24(ip));
  if (set.size !== before && set.size === TRUST_FANOUT_LOG) {
    logWould('would_deny', 'trust_fanout', uid, userAgent, requestPath, { uid, networks: set.size, ip });
  }
  if (set.size !== before && set.size === TRUST_FANOUT_REVOKE && TRUST_REVOKE_ENABLED) {
    revokeTrust(uid, set.size, ip, userAgent, requestPath);
  }
}

// D108 (2026-11-18): automatic loss of trust. One account seen on
// TRUST_FANOUT_REVOKE distinct /24s within an hour is a shared or scripted
// credential (logged-in humans peaked at 3 networks/hour, 2026-11-16..18; the
// solver fleet changes IP on almost every page). Its __bb_trust cookie stops
// bypassing anything for TRUST_REVOKE_HOURS: the browser is treated as
// anonymous (challenge, or the login wall on a hosting exit). Persisted to
// revoked-uids.json so a blue-green roll does not forgive it.
const TRUST_REVOKE_ENABLED = process.env.TRUST_REVOKE !== '0';
const TRUST_FANOUT_REVOKE = positiveIntEnv('TRUST_FANOUT_REVOKE', 15);
const TRUST_REVOKE_MS = positiveIntEnv('TRUST_REVOKE_HOURS', 24) * 60 * 60 * 1000;
const REVOKED_UIDS_FILE = path.join(LOG_DIR, 'revoked-uids.json');
const revokedUids = new Map();  // uid -> { untilMs, networks, revokedAt }

function revokeTrust(uid, networks, ip, userAgent, requestPath) {
  revokedUids.set(uid, { untilMs: Date.now() + TRUST_REVOKE_MS, networks, revokedAt: new Date().toISOString() });
  capMap(revokedUids, MAX_MAP_ENTRIES);
  logBlocked('trust_revoked', ip, userAgent,
    `uid ${uid}: ${networks} distinct networks within an hour - trust revoked for ${TRUST_REVOKE_MS / 3600000} h`,
    requestPath, { uid, networks });
  saveRevokedUids();
}

function isTrustRevoked(uid) {
  const rec = revokedUids.get(uid);
  if (!rec) return false;
  if (Date.now() < rec.untilMs) return true;
  revokedUids.delete(uid);
  return false;
}

function loadRevokedUids() {
  try {
    if (!fs.existsSync(REVOKED_UIDS_FILE)) return;
    const now = Date.now();
    for (const [uid, rec] of Object.entries(JSON.parse(fs.readFileSync(REVOKED_UIDS_FILE, 'utf8')))) {
      if (rec && rec.untilMs > now) revokedUids.set(uid, rec);
    }
    console.log(`[TRUST] Loaded ${revokedUids.size} active trust revocations`);
  } catch (err) {
    console.error('[TRUST] Failed to load revoked uids:', err.message);
  }
}

let revokedSaveScheduled = false;
function saveRevokedUids() {
  if (revokedSaveScheduled) return;
  revokedSaveScheduled = true;
  setTimeout(() => {
    revokedSaveScheduled = false;
    fs.writeFile(REVOKED_UIDS_FILE, JSON.stringify(Object.fromEntries(revokedUids)), (err) => {
      if (err) console.error('[TRUST] Failed to save revoked uids:', err.message);
    });
  }, 1000).unref();
}

// D108: manual account block list. blocked-uids.txt in LOG_DIR (the
// bot-blocker-logs volume on the host), one uid per line, `#` comments. Find
// an account's uid with substr(sha256(userIdentifier), 0, 16) - the app's
// BotTrustCookieSigner::uidFor. A request carrying that account's trust
// cookie gets a 403; without the cookie it is just an anonymous visitor.
// Re-read when the file changes (checked every BLOCKED_UIDS_RELOAD_S), no roll.
const BLOCKED_UIDS_FILE = path.join(LOG_DIR, 'blocked-uids.txt');
let blockedUids = new Set();
let blockedUidsMtime = -1;

function reloadBlockedUids() {
  let mtime = 0;
  try {
    mtime = fs.statSync(BLOCKED_UIDS_FILE).mtimeMs;
  } catch {
    mtime = 0;  // no file = empty list
  }
  if (mtime === blockedUidsMtime) return;
  blockedUidsMtime = mtime;
  const next = new Set();
  if (mtime) {
    try {
      for (const line of fs.readFileSync(BLOCKED_UIDS_FILE, 'utf8').split('\n')) {
        const uid = line.replace(/#.*/, '').trim();
        if (/^[0-9a-f]{16}$/.test(uid)) next.add(uid);
      }
    } catch (err) {
      console.error('[TRUST] Failed to read blocked uids:', err.message);
      return;
    }
  }
  blockedUids = next;
  console.log(`[TRUST] Account block list: ${blockedUids.size} uid(s)`);
}
setInterval(reloadBlockedUids, positiveIntEnv('BLOCKED_UIDS_RELOAD_S', 60) * 1000).unref();

setInterval(() => {
  for (const [name, set] of uaOnlySpread) {
    logBlocked('crawler_spread', '-', name, `${name}: ${set.size} distinct networks in the last hour`, '-',
      { crawler: name, networks: set.size });
  }
  uaOnlySpread.clear();
  for (const [uid, set] of trustFanout) {
    if (set.size >= 3) {
      logBlocked('trust_spread', '-', '-', `uid ${uid}: ${set.size} distinct networks in the last hour`, '-',
        { uid, networks: set.size });
    }
  }
  trustFanout.clear();
  const now = Date.now();
  for (const [key, ts] of wouldSeen) {
    if (now - ts > WOULD_DEDUP_MS) wouldSeen.delete(key);
  }
}, 60 * 60 * 1000).unref();
// Fraction of ALLOWED requests written to the JSONL log as `allow_sample`
// (2026-11-16, D96). Allowed traffic was invisible: a +85% day of 200s could
// not be attributed to anyone. 0 disables; default 1%.
const ALLOW_SAMPLE_RATE = (() => {
  const r = parseFloat(process.env.ALLOW_SAMPLE_RATE);
  return Number.isFinite(r) && r >= 0 && r <= 1 ? r : 0.01;
})();
// Response header on an ALLOW telling the app not to load Google Analytics
// for this visitor (Traefik forwardAuth `authResponseHeaders` copies it onto
// the upstream request and deletes any client-supplied copy). Set for
// hosting-class exits without a trust cookie: no human audience browses from
// a VM, and those are exactly the exits that solve the challenge for a living.
const ANALYTICS_HEADER = 'X-BB-Analytics';

// Locale scraping detection
const LOCALE_THRESHOLD = parseInt(process.env.LOCALE_THRESHOLD, 10) || 4;       // unique locales
const LOCALE_MIN_HITS = parseInt(process.env.LOCALE_MIN_HITS, 10) || 3;         // requests per locale
const LOCALE_WINDOW = parseInt(process.env.LOCALE_WINDOW, 10) || 60000;         // 1 minute
const BAN_DURATION = parseInt(process.env.BAN_DURATION, 10) || 30 * 24 * 60 * 60 * 1000; // 30 days
const BANNED_IPS_FILE = path.join(LOG_DIR, 'banned-ips.json');

// Page scraping detection (puzzle/profile pages) — windows in seconds
const PUZZLE_SCRAPE_THRESHOLD = parseInt(process.env.PUZZLE_SCRAPE_THRESHOLD, 10) || 40;
const PUZZLE_SCRAPE_WINDOW = (parseInt(process.env.PUZZLE_SCRAPE_WINDOW, 10) || 300) * 1000;  // 300s = 5 min
const PROFILE_SCRAPE_THRESHOLD = parseInt(process.env.PROFILE_SCRAPE_THRESHOLD, 10) || 40;
const PROFILE_SCRAPE_WINDOW = (parseInt(process.env.PROFILE_SCRAPE_WINDOW, 10) || 300) * 1000;  // 300s = 5 min
const SCRAPE_STRIKES_FOR_BAN = parseInt(process.env.SCRAPE_STRIKES_FOR_BAN, 10) || 3;
const SCRAPE_STRIKE_WINDOW = (parseInt(process.env.SCRAPE_STRIKE_WINDOW, 10) || 86400) * 1000;  // 86400s = 24h


// =============================================================================
// STATIC ASSET PATTERNS (excluded from rate limiting)
// =============================================================================

const STATIC_ASSET_PATTERNS = [
  /^\/build\//i,
  /^\/css\//i,
  /^\/fonts\//i,
  /^\/img\//i,
  /^\/ads\.txt$/i,
  /^\/android/i,
  /^\/favicon/i,
  /^\/humans\.txt$/i,
  /^\/manifest\.json$/i,
  /^\/robots\.txt$/i,
  /^\/security\.txt$/i,
  // Microsoft's publisher-domain verification file (Sign in with Microsoft
  // app registration). Microsoft's verifier is a server-side fetch whose UA
  // is undocumented (a bare HTTP client may send none -> the empty-UA rule)
  // and comes from Azure ranges - it must never meet a block or challenge.
  /^\/\.well-known\/microsoft-identity-association\.json$/i,
  /^\/service-worker\.js$/i,
  /^\/site\.webmanifest$/i,
  /^\/apple/i,
  /^\/mstile/i,
  /^\/safari/i,
  // Top-level sprite/static files fetched alongside HTML pages — must NOT
  // hit UA-velocity strike accounting. A single page load fetches HTML +
  // /rank-icons-sprite.svg + /stat-icons-sprite.svg + /difficulty-icons-sprite.svg
  // in parallel; before this, that racked up 3 strikes in <20ms and permabanned
  // real users on first click. Matches root-level files with static extensions.
  // Image: svg/png/jpg/jpeg/gif/webp/avif/heic/heif/bmp/tiff/tif/ico
  // Font:  woff/woff2/ttf/eot/otf
  // Media: mp4/webm/ogv/mov/m4v/mp3/wav/ogg/m4a/opus/flac/aac
  // Other: css/map/pdf
  /^\/[^/?]+\.(svg|png|jpg|jpeg|gif|webp|avif|heic|heif|bmp|tiff|tif|ico|woff2?|ttf|eot|otf|css|map|pdf|mp4|webm|ogv|mov|m4v|mp3|wav|ogg|m4a|opus|flac|aac)(\?|$)/i,
];

function isStaticAsset(requestPath) {
  return STATIC_ASSET_PATTERNS.some(pattern => pattern.test(requestPath));
}

// =============================================================================
// SEARCH ENGINE BOT WHITELIST (bypass all blocking)
// =============================================================================

// Three trust tiers (a bare UA regex is spoofable — 425+ "Googlebot" UAs over
// HTTP/1.1 were observed passing here 2026-07-30..08-02 with zero verification):
//   rdns: [...]  — verify with forward-confirmed reverse DNS (the procedure
//                  Google/Bing/Seznam document). Verified → unlimited pass.
//                  Definitive mismatch (PTR elsewhere / NXDOMAIN) → treated as
//                  a FAKE crawler: falls through to the normal pipeline (where
//                  datacenter-ASN scoring usually catches it). DNS
//                  timeout/SERVFAIL → fail OPEN (whitelist honored, uncached):
//                  never 403 real Googlebot because a resolver hiccuped.
//   asn: <n>     — forward verification by ASN membership instead of rDNS, for
//                  operators who publish IP ranges but no PTR records (Meta).
//                  Backed by geodb/crawler-asn.bin; a MISSING range file or an
//                  IPv6 client yields no verdict and falls through to the
//                  capped UA-only path — never to `fake`.
//   capped: true — UA-only whitelist with a WHITELIST_BOT_CAP/min per-IP
//                  budget (429 above it). For preview bots that fetch a page
//                  per human share, the cap is unreachable; for a scraper
//                  hiding behind "WhatsApp" it's a ceiling. (meta-webindexer
//                  sat here capped until 2026-11-09; a per-IP cap does nothing
//                  against a fleet of /24s, so it is now in BLOCKED_BOTS.)
//   (neither)    — legacy unlimited UA-only pass. Reserved for Stripe
//                  webhooks: capping those risks dropped payment events, a
//                  far worse failure than tolerating a spoofable UA that was
//                  spoofable yesterday too.
const RDNS_GOOGLE = ['.googlebot.com', '.google.com'];
const RDNS_BING = ['.search.msn.com'];

// Meta is verified by ASN, not rDNS: their fetcher addresses have NO PTR record
// at all (checked against 8.8.8.8, 1.1.1.1 and our own resolver), so the
// forward-confirmed check below can only ever return 'fake' for them. It did —
// 50 583 Meta requests were misclassified in 48h and 1 508 of those were
// facebookexternalhit, i.e. broken Facebook/WhatsApp/Messenger link previews.
// Meta documents verification against their published ranges / AS32934.
const ASN_META = 32934;

const WHITELISTED_BOTS = [
  // Google (https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers)
  { pattern: /Googlebot/i, name: 'Googlebot', rdns: RDNS_GOOGLE },
  { pattern: /Google-InspectionTool/i, name: 'Google Search Console', rdns: RDNS_GOOGLE },
  { pattern: /Storebot-Google/i, name: 'Google Merchant', rdns: RDNS_GOOGLE },
  { pattern: /AdsBot-Google/i, name: 'Google Ads', rdns: RDNS_GOOGLE },
  { pattern: /Mediapartners-Google/i, name: 'Google AdSense', rdns: RDNS_GOOGLE },
  { pattern: /APIs-Google/i, name: 'Google APIs', rdns: RDNS_GOOGLE },
  { pattern: /GoogleOther/i, name: 'Google Other', rdns: RDNS_GOOGLE },

  // Bing / Microsoft
  { pattern: /bingbot/i, name: 'Bingbot', rdns: RDNS_BING },
  { pattern: /msnbot/i, name: 'MSN Bot', rdns: RDNS_BING },
  { pattern: /AdIdxBot/i, name: 'Microsoft Advertising', rdns: RDNS_BING },
  { pattern: /BingPreview/i, name: 'Bing Preview', rdns: RDNS_BING },

  // Other search engines
  { pattern: /YandexBot/i, name: 'Yandex', rdns: ['.yandex.ru', '.yandex.net', '.yandex.com'] },
  { pattern: /DuckDuckBot/i, name: 'DuckDuckGo', capped: true },  // publishes IPs, not rDNS
  { pattern: /Slurp/i, name: 'Yahoo', capped: true },
  { pattern: /Applebot/i, name: 'Apple (Siri/Spotlight)', rdns: ['.applebot.apple.com'] },
  { pattern: /Qwant/i, name: 'Qwant', capped: true },
  { pattern: /SeznamBot/i, name: 'Seznam', rdns: ['.seznam.cz'] },

  // Social media previews (important for link sharing/SEO) — fetch one page
  // per human share; the per-IP cap never touches that, only impersonators.
  // Only Meta's LINK-PREVIEW fetcher is whitelisted. Its indexing/AI crawlers
  // (meta-webindexer, meta-externalagent) are in BLOCKED_BOTS since 2026-11-09.
  { pattern: /facebookexternalhit/i, name: 'Facebook', asn: ASN_META, capped: true },
  { pattern: /Twitterbot/i, name: 'Twitter/X', capped: true },
  { pattern: /LinkedInBot/i, name: 'LinkedIn', capped: true },
  { pattern: /WhatsApp/i, name: 'WhatsApp', capped: true },
  { pattern: /Slackbot/i, name: 'Slack', capped: true },
  { pattern: /TelegramBot/i, name: 'Telegram', capped: true },
  { pattern: /Discordbot/i, name: 'Discord', capped: true },

  // Monitoring
  { pattern: /SentryUptimeBot/i, name: 'Sentry Uptime', capped: true },
  // Stripe webhooks: uncapped (never risk dropped payment events) but ONLY for
  // a POST to the webhook route (D98). Until 2026-11-16 any method on any path
  // passed with this UA — and the UA came from a client-settable header.
  { pattern: /Stripe\//i, name: 'Stripe', methods: ['POST'], paths: ['/webhook/stripe'] },
];

// Apple's on-device link-preview fetcher (iMessage, Mail, Notes) — a frozen
// 2015 Safari UA with Meta/Twitter tokens appended. It runs on the sharer's
// device (home ISPs, iCloud Private Relay), so the Meta ASN check below
// labelled it "fake Facebook" and the ladder challenged ~39% of previews
// (D98: 965 risk challenges / 910 Traefik 403s in a week). Exact match, low
// per-IP cap: a preview is one fetch per share.
const APPLE_LINK_PREVIEW_UA = /^Mozilla\/5\.0 \(Macintosh; Intel Mac OS X 10_11_1\) AppleWebKit\/601\.2\.4 \(KHTML, like Gecko\) Version\/9\.0\.1 Safari\/601\.2\.4 facebookexternalhit\/1\.1 Facebot Twitterbot\/1\.0$/;
WHITELISTED_BOTS.unshift({ pattern: APPLE_LINK_PREVIEW_UA, name: 'Apple link preview', capped: true, cap: 10 });

// ---------------------------------------------------------------------------
// Forward-confirmed rDNS: PTR of the IP must end with an allowed suffix AND
// the PTR hostname must resolve back to the same IP. Results cached per IP
// (positive 48h, negative 24h). dnsReverse/dnsResolve are indirected so tests
// inject a fake resolver.
// ---------------------------------------------------------------------------

const RDNS_TIMEOUT_MS = parseInt(process.env.RDNS_TIMEOUT_MS, 10) || 1500;
const RDNS_OK_TTL_MS = 48 * 60 * 60 * 1000;
const RDNS_FAKE_TTL_MS = 24 * 60 * 60 * 1000;

let dnsReverse = (ip) => dns.promises.reverse(ip);
let dnsResolve = (hostname) => dns.promises.resolve4(hostname);

function _setDnsForTests(reverseFn, resolveFn, clearLastOk = true) {
  dnsReverse = reverseFn;
  dnsResolve = resolveFn;
  rdnsCache.clear();
  if (clearLastOk) rdnsLastOk.clear();
}

const rdnsCache = new Map();  // ip -> { state: 'ok'|'fake', exp }

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('rdns timeout')), ms);
    timer.unref?.();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function verifyCrawlerRdns(ip, suffixes) {
  const cached = rdnsCache.get(ip);
  if (cached && cached.exp > Date.now()) return cached.state;

  let state;
  try {
    const ptrs = await withTimeout(dnsReverse(ip), RDNS_TIMEOUT_MS);
    const host = (ptrs || []).find(h => {
      const lower = h.toLowerCase();
      return suffixes.some(s => lower.endsWith(s));
    });
    if (!host) {
      state = 'fake';
    } else {
      const addrs = await withTimeout(dnsResolve(host), RDNS_TIMEOUT_MS);
      state = (addrs || []).includes(ip) ? 'ok' : 'fake';
    }
    if (state === 'ok') {
      rdnsLastOk.set(ip, { host: host.toLowerCase(), exp: Date.now() + RDNS_LAST_OK_TTL_MS });
      capMap(rdnsLastOk, MAX_MAP_ENTRIES);
    }
  } catch (err) {
    // NXDOMAIN/no-PTR is a definitive answer — a real crawler always has one.
    // Anything else (timeout, SERVFAIL) is OUR uncertainty, no cache. An IP
    // that verified within RDNS_LAST_OK_TTL_MS keeps its last 'ok' verdict, so
    // a resolver hiccup never changes how a known crawler is treated (D98).
    if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) {
      state = 'fake';
    } else {
      const lastOk = rdnsLastOk.get(ip);
      if (lastOk && lastOk.exp > Date.now()) return 'ok';
      return 'error';
    }
  }

  rdnsCache.set(ip, { state, exp: Date.now() + (state === 'ok' ? RDNS_OK_TTL_MS : RDNS_FAKE_TTL_MS) });
  capMap(rdnsCache, MAX_MAP_ENTRIES);
  return state;
}

// Last forward-confirmed PTR per crawler IP (ip -> { host, exp }), kept far
// longer than the verdict cache: survives DNS errors, and tells which suffix
// verified the IP (telemetry for the `.google.com` Googlebot proof).
const rdnsLastOk = new Map();
const RDNS_LAST_OK_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const crawlerBuckets = new Map();  // "name|ip" -> { count, windowStart }

function isCrawlerCapped(name, ip, cap = WHITELIST_BOT_CAP) {
  const key = name + '|' + ip;
  const now = Date.now();
  const record = crawlerBuckets.get(key);
  if (!record || now - record.windowStart > 60000) {
    crawlerBuckets.set(key, { count: 1, windowStart: now });
    capMap(crawlerBuckets, MAX_MAP_ENTRIES);
    return false;
  }
  record.count++;
  return record.count > cap;
}

/**
 * Whitelist resolution for a matched crawler UA.
 * Returns null (no whitelist claim) or:
 *   { name, allow: true }  — pass unlimited
 *   { name, capped: true } — over the per-IP budget, serve 429
 *   { name, fake: true }   — rDNS-refuted impersonator: fall through to the
 *                            normal pipeline (NOT an instant block — a real
 *                            human behind a weird UA string deserves the same
 *                            scoring/challenges as everyone else)
 */
async function checkWhitelistedBot(userAgent, ip, method = 'GET', requestPath = '/') {
  if (!userAgent) return null;
  for (const entry of WHITELISTED_BOTS) {
    if (!entry.pattern.test(userAgent)) continue;
    if (entry.methods && !entry.methods.includes(method)) continue;
    if (entry.paths && !entry.paths.includes(requestPath.split('?')[0])) continue;
    if (entry.rdns) {
      const state = await verifyCrawlerRdns(ip, entry.rdns);
      if (state === 'fake') return { name: entry.name, fake: true };
      // 'ok' → verified; 'error' → still allowed today (uncached, retried next
      // request) — logged so the D98 capped-allow can be judged on data.
      if (state === 'error') {
        logWould('would_cap', 'rdns_error_unverified', ip, userAgent, requestPath, { crawler: entry.name });
      } else if (entry.rdns === RDNS_GOOGLE) {
        // `.google.com` PTRs are Google's user-triggered fetcher mask, not
        // Googlebot's (google-proxy-*.google.com). Log what still relies on it.
        const host = rdnsLastOk.get(ip)?.host || '';
        if (!host.endsWith('.googlebot.com') && !isGooglePublishedIp(ip)) {
          logWould('would_deny', 'google_com_rdns_only', ip, userAgent, requestPath, { crawler: entry.name, ptr: host });
        }
      }
    }
    if (entry.asn) {
      // Only a LOADED range file can prove an impostor. With no data (missing
      // file, RIPEstat down at build time, or an IPv6 client — the ranges are
      // IPv4-only) we must not invent a verdict: fall through to the capped
      // UA-only whitelist, which bounds the damage at WHITELIST_BOT_CAP/min.
      if (crawlerAsnDataLoaded() && ipToInt(ip) !== 0 && crawlerAsn(ip) !== entry.asn) {
        return { name: entry.name, fake: true };
      }
    }
    if (entry.capped && isCrawlerCapped(entry.name, ip, entry.cap || WHITELIST_BOT_CAP)) {
      return { name: entry.name, capped: true };
    }
    if (!entry.rdns && !entry.asn && entry.capped) recordUaOnlySpread(entry.name, ip);
    return { name: entry.name, allow: true };
  }
  return null;
}

// =============================================================================
// GOOGLE PUBLISHED FETCHER RANGES (IP-verified, UA-independent)
//
// Google's user-triggered fetchers do not say "Googlebot" and often say almost
// nothing: the OAuth brand-verification fetcher sends the bare UA "Google",
// Read Aloud sends a mobile-Chrome UA, Lens sends "Google-Lens", Docs/Gmail
// link previews send a desktop-Chrome UA with ",gzip(gfe)". None matched the
// UA whitelist, all come from a Google ASN (dc_asn +40) without a browser
// header set, so the risk ladder challenged every one of them — on 2026-09-29
// that made Google's OAuth brand verification see the challenge page instead
// of the home page and privacy policy, and reject the app ("home page behind a
// login page", "privacy policy does not have sufficient content").
//
// Google documents verification for these by its published IP lists, not by
// UA. Addresses cannot be spoofed here (Traefik scrubs X-Forwarded-For), and
// the lists are small dedicated /27s, not general Google Cloud space — a GCP
// VM does NOT land in them. Membership still gets a per-IP cap
// (WHITELIST_BOT_CAP/min): user-triggered fetchers fetch on behalf of people
// and should never approach it.
//
// Data: baked at image build (scripts/build-geodb.mjs → geodb/google-ranges.json)
// and refreshed at runtime every GOOGLE_RANGES_REFRESH_HOURS (default 24, 0 =
// off). Everything fails OPEN in the sense of "no extra privileges": no data
// just means these requests go through the normal pipeline as before.
// =============================================================================

const GOOGLE_RANGE_LISTS = {
  'common-crawlers': 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
  'special-crawlers': 'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
  'user-triggered-fetchers': 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
  'user-triggered-fetchers-google': 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
};
const GOOGLE_RANGES_REFRESH_HOURS = process.env.GOOGLE_RANGES_REFRESH_HOURS === undefined
  ? 24 : parseFloat(process.env.GOOGLE_RANGES_REFRESH_HOURS) || 0;

// list name -> array of CIDR strings; the BlockList is rebuilt from it.
const googleRanges = { lists: {}, blockList: new net.BlockList(), count: 0, source: 'none' };

// Extracts CIDRs from one of Google's JSON documents ({ prefixes: [{ ipv4Prefix
// | ipv6Prefix }] }). Returns null on anything unexpected.
function parseGoogleRangeDocument(doc) {
  if (!doc || !Array.isArray(doc.prefixes)) return null;
  const cidrs = [];
  for (const p of doc.prefixes) {
    const cidr = p && (p.ipv4Prefix || p.ipv6Prefix);
    if (typeof cidr === 'string' && /^[0-9a-fA-F.:]+\/\d{1,3}$/.test(cidr)) cidrs.push(cidr);
  }
  return cidrs;
}

function rebuildGoogleBlockList() {
  const bl = new net.BlockList();
  let count = 0;
  for (const cidrs of Object.values(googleRanges.lists)) {
    for (const cidr of cidrs) {
      const [addr, bits] = cidr.split('/');
      const type = net.isIPv6(addr) ? 'ipv6' : (net.isIPv4(addr) ? 'ipv4' : null);
      if (!type) continue;
      try {
        bl.addSubnet(addr, parseInt(bits, 10), type);
        count++;
      } catch { /* malformed prefix — skip it, keep the rest */ }
    }
  }
  googleRanges.blockList = bl;
  googleRanges.count = count;
  // Google's USER-CONTROLLED fetchers (Apps Script etc.) on their own (D98
  // telemetry): an IP only in this list would be scored, not allowed.
  const user = new net.BlockList();
  const googleOwned = new net.BlockList();
  for (const [name, cidrs] of Object.entries(googleRanges.lists)) {
    const target = name === 'user-triggered-fetchers' ? user : googleOwned;
    for (const cidr of cidrs) {
      const [addr, bits] = cidr.split('/');
      const type = net.isIPv6(addr) ? 'ipv6' : (net.isIPv4(addr) ? 'ipv4' : null);
      if (!type) continue;
      try { target.addSubnet(addr, parseInt(bits, 10), type); } catch { /* skip */ }
    }
  }
  googleRanges.userControlled = user;
  googleRanges.googleOwned = googleOwned;
}

// lists: { name: [cidr, ...] } — merges over what is loaded, so a list that
// failed to refresh keeps its previous (baked or last-good) contents.
function setGoogleRanges(lists, source) {
  let changed = false;
  for (const [name, cidrs] of Object.entries(lists || {})) {
    if (Array.isArray(cidrs) && cidrs.length > 0) {
      googleRanges.lists[name] = cidrs;
      changed = true;
    }
  }
  if (changed) {
    rebuildGoogleBlockList();
    googleRanges.source = source;
  }
  return changed;
}

function loadGoogleRanges(dir) {
  googleRanges.lists = {};
  rebuildGoogleBlockList();
  googleRanges.source = 'none';
  try {
    const baked = JSON.parse(fs.readFileSync(path.join(dir, 'google-ranges.json'), 'utf8'));
    setGoogleRanges(baked.lists, `baked ${baked.built || 'unknown'}`);
    console.log(`[GOOGLE] Loaded ${googleRanges.count} published fetcher prefixes (${googleRanges.source})`);
  } catch (err) {
    console.log(`[GOOGLE] No baked fetcher ranges (${err.message}) — waiting for runtime refresh`);
  }
}

async function refreshGoogleRanges(fetchFn = fetch) {
  const fresh = {};
  await Promise.all(Object.entries(GOOGLE_RANGE_LISTS).map(async ([name, url]) => {
    try {
      const res = await fetchFn(url, { redirect: 'follow', signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const cidrs = parseGoogleRangeDocument(await res.json());
      if (!cidrs || cidrs.length === 0) throw new Error('no prefixes');
      fresh[name] = cidrs;
    } catch (err) {
      console.log(`[GOOGLE] refresh of ${name} failed (${err.message}) — keeping previous data`);
    }
  }));
  if (setGoogleRanges(fresh, `refreshed ${new Date().toISOString()}`)) {
    console.log(`[GOOGLE] ${googleRanges.count} published fetcher prefixes after refresh`);
  }
}

function normalizeClientIp(ip) {
  if (typeof ip !== 'string') return '';
  return ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7)) ? ip.slice(7) : ip;
}

// True when the IP is ONLY in Google's user-controlled fetcher list.
function isGoogleUserControlledOnly(ip) {
  if (googleRanges.count === 0 || !googleRanges.userControlled) return false;
  const addr = normalizeClientIp(ip);
  const type = net.isIPv4(addr) ? 'ipv4' : (net.isIPv6(addr) ? 'ipv6' : null);
  if (!type) return false;
  return googleRanges.userControlled.check(addr, type) && !googleRanges.googleOwned.check(addr, type);
}

function isGooglePublishedIp(ip) {
  if (googleRanges.count === 0) return false;
  const addr = normalizeClientIp(ip);
  const type = net.isIPv4(addr) ? 'ipv4' : (net.isIPv6(addr) ? 'ipv6' : null);
  if (!type) return false;
  return googleRanges.blockList.check(addr, type);
}

// =============================================================================
// RISK-LADDER EXEMPT PATHS
//
// The pages app-store / OAuth reviewers (Google, Meta, Apple) and their
// fetchers open to judge the app: home page, privacy policy, terms, data
// deletion — in every locale. They are cheap, contain nothing worth scraping,
// and a challenge there fails a brand review. Exempt from the heuristic risk
// ladder ONLY: deterministic rules (named bad bots, exploit paths, permabans,
// rate limits) still apply. Keep in sync with the app's routes
// (HomepageController, PrivacyPolicyController, TermsOfServiceController,
// DataDeletionController).
// =============================================================================

const SCORING_EXEMPT_PATHS = new Set([
  // homepage
  '/', '/cs', '/en', '/es', '/ja', '/fr', '/de',
  // privacy_policy
  '/zasady-ochrany-osobnich-udaju', '/en/privacy-policy', '/es/politica-privacidad',
  '/ja/プライバシー', '/fr/politique-confidentialite', '/de/datenschutz',
  // terms_of_service
  '/obchodni-podminky', '/en/terms-of-service', '/es/terminos-servicio',
  '/ja/利用規約', '/fr/conditions-service', '/de/nutzungsbedingungen',
  // data_deletion
  '/smazani-udaju', '/en/data-deletion', '/es/eliminacion-datos',
  '/ja/データ削除', '/fr/suppression-donnees', '/de/datenloeschung',
]);

// Sign-in / registration / magic-link / social-login pages (any locale
// prefix). They hold nothing worth scraping and they are the way to the
// __bb_trust cookie: the challenge page itself tells people to log in, so the
// login page must not challenge them again (D96 follow-up, 2026-11-16).
// Deterministic rules and rate limits still apply; POSTs are never scored.
const AUTH_PAGE_PATTERN = /^(?:\/(?:en|es|ja|fr|de|cs))?\/(?:login|register|login-link)(?:\/|$)/;

function isScoringExemptPath(requestPath) {
  let p = String(requestPath || '/').split('?')[0].split('#')[0];
  try { p = decodeURIComponent(p); } catch { /* keep raw */ }
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return SCORING_EXEMPT_PATHS.has(p) || AUTH_PAGE_PATTERN.test(p);
}

// =============================================================================
// BLOCKED PATHS (immediate block for suspicious/malicious requests)
// =============================================================================

const BLOCKED_PATHS = [
    { pattern: /\/wp-content\//i, reason: 'WordPress exploit attempt' },
    { pattern: /\/wp-admin/i, reason: 'WordPress exploit attempt' },
    { pattern: /\/wp-includes\//i, reason: 'WordPress exploit attempt' },
    { pattern: /\/\.env/i, reason: 'Environment file access attempt' },
    { pattern: /\/\.git/i, reason: 'Git repository access attempt' },
];

// =============================================================================
// BLOCKED BOTS
// =============================================================================

const BLOCKED_BOTS = [
    // =========================================================================
    // KNOWN BAD BOTS (by name - always safe)
    // =========================================================================
    { pattern: /AliyunSecBot/i, reason: 'Chinese security scanner bot' },
    { pattern: /PetalBot/i, reason: 'Huawei search engine bot' },
    { pattern: /SemrushBot/i, reason: 'SEO scraper bot' },
    { pattern: /AhrefsBot/i, reason: 'SEO scraper bot' },
    { pattern: /DotBot/i, reason: 'SEO scraper bot' },
    { pattern: /MJ12bot/i, reason: 'SEO scraper bot' },
    { pattern: /SERankingBacklinksBot/i, reason: 'SEO scraper bot (SE Ranking)' },
    { pattern: /Bytespider|TikTokSpider/i, reason: 'TikTok content scraper' },
    { pattern: /AwarioSmartBot/i, reason: 'Social monitoring bot' },
    { pattern: /BrightEdge Crawler/i, reason: 'SEO crawler' },
    { pattern: /GPTBot/i, reason: 'OpenAI training crawler' },
    { pattern: /ClaudeBot/i, reason: 'Anthropic training crawler' },
    { pattern: /Amazonbot/i, reason: 'Amazon Alexa indexer' },
    { pattern: /Barkrowler/i, reason: 'SEO crawler bot (Barkrowler)' },
    { pattern: /MySpeedPuzzling-Research-Scraper/i, reason: 'Known data scraper' },
    { pattern: /Sogou/i, reason: 'Sogou spider (Chinese search engine)' },
    { pattern: /HeadlessChrome/i, reason: 'Headless browser automation' },
    { pattern: /newsai/i, reason: 'AI news scraper' },
    { pattern: /BacklinksExtendedBot/i, reason: 'SEO backlinks crawler' },
    { pattern: /PerplexityBot/i, reason: 'AI answer engine crawler' },
    { pattern: /CensysInspect/i, reason: 'Internet scanner' },
    { pattern: /Baiduspider/i, reason: 'Baidu spider (aggressive cross-locale crawler)' },
    { pattern: /DataForSeoBot/i, reason: 'SEO scraper bot (DataForSEO)' },
    { pattern: /ChatGPT-User/i, reason: 'OpenAI ChatGPT browsing' },
    { pattern: /YouBot/i, reason: 'You.com AI bot' },
    { pattern: /SpiderLing/i, reason: 'NLP research crawler' },
    { pattern: /InternetMeasurement/i, reason: 'Internet scanner' },
    { pattern: /Palo Alto Networks/i, reason: 'Security scanner' },
    // Meta's indexing / AI-training crawlers (2026-11-09). From 57.141.x they
    // hit /{locale}/login, /feedback and social-login start ~2,500×/hour -
    // pages with nothing to index (Sentry: GET login 291k/week). They used to
    // be on the capped whitelist; a per-IP cap is no use against a fleet.
    // NOT matched (on purpose): facebookexternalhit (link previews of shared
    // results - whitelisted above), meta-externalfetcher (user-initiated
    // fetches) and Facebot. Also disallowed in the app's robots.txt.
    { pattern: /meta-webindexer/i, reason: 'Meta AI search indexer (meta-webindexer)' },
    { pattern: /meta-externalagent/i, reason: 'Meta AI training crawler (meta-externalagent)' },
    // ~100/hour from Google Cloud on noindex /{locale}/result/{uuid} pages.
    { pattern: /ShapBot/i, reason: 'ShapBot crawler (noindex result pages)' },
    // ~5,700 pages/day (2026-11-17/18) from two Malaysian broadband IPs, no
    // Accept-Language, no cookies, scored just under the challenge threshold.
    // Not a search engine anyone documents; a bare self-declared indexer.
    { pattern: /PageIndexer/i, reason: 'PageIndexer scraper (undocumented indexer)' },

    // =========================================================================
    // FAKE/IMPOSSIBLE BROWSER SIGNATURES
    //
    // challenge: true — these match USER-AGENT STRINGS, not declared bot names,
    // and the same strings are produced by privacy tools real humans run:
    // UA-freezing browsers emit the dead-device string, anti-fingerprinting
    // extensions randomize into impossible OS+version combos, and Opera Mini's
    // proxy rendering still sends Presto. The signal stays (bots don't solve
    // challenges); the humans get a way through. The two rules removed for
    // mass-FPs (b447f35, bd52e3f) would have survived with this flag.
    // =========================================================================

    // Opera Presto engine discontinued in 2013 — all modern Opera uses Chromium
    { pattern: /Presto\/\d/i, reason: 'Fake Opera bot (Presto engine discontinued 2013)', challenge: true },

    // Exact bot fingerprint: Chrome 48.0.2564.116 (Jan 2016) shared across 56+ Chinese IPs
    // No real user runs Chrome 48 in 2026; WOW64 (32-bit on 64-bit) is also very rare
    { pattern: /Chrome\/48\.0\.2564\.116/, reason: 'Fake Chrome 48 bot signature (shared across many CN IPs)', challenge: true },

    // Nexus 5 was discontinued in 2015, Android 6.0 (Marshmallow) EOL 2018
    // No real user on a 10-year-old phone with EOL OS in 2026 — but privacy
    // tools DO freeze UAs on exactly this string (24k distinct IPs / 8 days,
    // ~1 block per IP: proxy rotation with possible humans hidden inside)
    { pattern: /Android 6\.0; Nexus 5 Build/i, reason: 'Dead device (Nexus 5 discontinued 2015, Android 6 EOL 2018)', challenge: true },

    // =========================================================================
    // IMPOSSIBLE BROWSER COMBINATIONS (verified safe)
    // =========================================================================

    // Windows 7 (NT 6.1) + Chrome 110+ is impossible
    // Chrome 109 was the LAST version supporting Windows 7 (February 2023)
    // Source: Google officially ended support
    { pattern: /Windows NT 6\.1.*Chrome\/1[1-9][0-9]\./i, reason: 'Impossible: Windows 7 + Chrome 110+ (support ended Feb 2023)', challenge: true },
    { pattern: /Windows NT 6\.1.*Chrome\/[2-9][0-9]{2}\./i, reason: 'Impossible: Windows 7 + Chrome 200+', challenge: true },

    // Windows Vista (NT 6.0) + Chrome 50+ is impossible
    // Chrome 49 was the LAST version supporting Vista (April 2016)
    { pattern: /Windows NT 6\.0.*Chrome\/[5-9][0-9]\./i, reason: 'Impossible: Windows Vista + Chrome 50+', challenge: true },
    { pattern: /Windows NT 6\.0.*Chrome\/1[0-9]{2}\./i, reason: 'Impossible: Windows Vista + Chrome 100+', challenge: true },

    // Windows XP (NT 5.1) + Chrome 50+ is impossible
    // Chrome 49 was the LAST version supporting XP (April 2016)
    { pattern: /Windows NT 5\.1.*Chrome\/[5-9][0-9]\./i, reason: 'Impossible: Windows XP + Chrome 50+', challenge: true },
    { pattern: /Windows NT 5\.1.*Chrome\/1[0-9]{2}\./i, reason: 'Impossible: Windows XP + Chrome 100+', challenge: true },
];

// =============================================================================
// CIDR BLOCKLIST (known botnet subnets)
// =============================================================================

const BLOCKED_CIDRS = [
  { prefix: '43.104.33.', reason: 'Known Chinese botnet subnet' },
  // 43.172.0.0/15 (43.172.x + 43.173.x) is Tencent Cloud end to end — 2 305
  // distinct IPs from it crawled /en/ with rotating Win10/Chrome UAs
  // 2026-07-29..08-02 (99.97% already 403'd by the combo rule; this closes
  // the non-Win10-UA remainder). Supersedes the old per-/24 43.173.168-175
  // entries.
  { prefix: '43.172.', reason: 'Tencent Cloud botnet range (43.172.0.0/15)' },
  { prefix: '43.173.', reason: 'Tencent Cloud botnet range (43.172.0.0/15)' },
  // Baidu ASN 38365 — commercial crawler infrastructure, no real users
  { prefix: '220.181.', reason: 'Baidu crawler ASN (commercial infra, no real users)' },
  // Indonesian residential-proxy botnet subnet — 121+ distinct IPs observed in
  // 8h all sharing the same fake Chrome/133.0.6943.141 UA hitting Japanese-locale
  // UUID pages.
  { prefix: '202.46.62.', reason: 'Indonesian residential-proxy botnet subnet (fake Chrome/133 UA farm)' },
];

function isBlockedSubnet(ip) {
  if (!ip) return null;
  for (const cidr of BLOCKED_CIDRS) {
    if (ip.startsWith(cidr.prefix)) {
      return cidr.reason;
    }
  }
  return null;
}

// =============================================================================
// CHINESE BOTNET DETECTION (combination-based)
// =============================================================================

/**
 * Detects Chinese cloud botnet based on IP range and user agent.
 * Pattern: 43.x IP (Tencent/Alibaba APNIC block) + Windows 10 + Chrome (any version).
 * The httpVersion check was removed — ForwardAuth always uses HTTP/1.1 internally,
 * so req.httpVersion is always '1.1' regardless of original client protocol.
 */
function isChineseBotnet(ip, userAgent) {
  if (!ip || !ip.startsWith('43.')) return false;
  return /Windows NT 10\.0.*Chrome\/\d+\./.test(userAgent || '');
}

/**
 * Detects fake iOS bot from Chinese cloud
 * iOS 13.2.3 is from November 2019 - no real user has this in 2025
 */
function isFakeIOSBot(ip, userAgent) {
  if (!ip || !ip.startsWith('43.')) return false;
  return /iPhone OS 13_2_3/.test(userAgent || '');
}

// =============================================================================
// CLOUD BOTNET DETECTION (HTTP/1.1 protocol-based)
// Requires X-Original-Protocol header from Traefik plugin
// =============================================================================

/**
 * Cloud provider CIDR ranges used by the scraping botnet.
 * Sources: ipverse/asn-ip (daily-updated ASN IP blocks)
 *
 * BytePlus/ByteDance (AS150436): 150.5.128.0/17, 163.7.0.0/17, 101.47.0.0/18
 * Tencent Cloud (AS132203, AS45090): 129.226.0.0/16, 170.106.0.0/16,
 *   119.28.0.0/15, 162.62.0.0/16, 49.51.0.0/16
 * Alibaba Cloud (AS45102): 47.52.0.0/14, 47.74.0.0/15, 47.88.0.0/14,
 *   47.236.0.0/14, 47.244.0.0/14, 8.208.0.0/12
 *
 * Note: 43.x is handled separately by isChineseBotnet() above.
 */
const CLOUD_PROVIDER_CIDRS = [
  // BytePlus / ByteDance
  { network: 0x96058000, mask: 0xFFFF8000, name: 'BytePlus' },        // 150.5.128.0/17
  { network: 0xA3070000, mask: 0xFFFF8000, name: 'BytePlus' },        // 163.7.0.0/17
  { network: 0x652F0000, mask: 0xFFFFC000, name: 'BytePlus' },        // 101.47.0.0/18

  // Tencent Cloud
  { network: 0x81E20000, mask: 0xFFFF0000, name: 'Tencent Cloud' },   // 129.226.0.0/16
  { network: 0xAA6A0000, mask: 0xFFFF0000, name: 'Tencent Cloud' },   // 170.106.0.0/16
  { network: 0x771C0000, mask: 0xFFFE0000, name: 'Tencent Cloud' },   // 119.28.0.0/15
  { network: 0xA23E0000, mask: 0xFFFF0000, name: 'Tencent Cloud' },   // 162.62.0.0/16
  { network: 0x31330000, mask: 0xFFFF0000, name: 'Tencent Cloud' },   // 49.51.0.0/16

  // Alibaba Cloud (AS45102) — extensive 47.x allocation
  { network: 0x2F340000, mask: 0xFFFC0000, name: 'Alibaba Cloud' },   // 47.52.0.0/14  (47.52-55)
  { network: 0x2F380000, mask: 0xFFFE0000, name: 'Alibaba Cloud' },   // 47.56.0.0/15  (47.56-57)
  { network: 0x2F4A0000, mask: 0xFFFE0000, name: 'Alibaba Cloud' },   // 47.74.0.0/15  (47.74-75)
  { network: 0x2F4C0000, mask: 0xFFFC0000, name: 'Alibaba Cloud' },   // 47.76.0.0/14  (47.76-79)
  { network: 0x2F500000, mask: 0xFFF00000, name: 'Alibaba Cloud' },   // 47.80.0.0/12  (47.80-95)
  { network: 0x2F600000, mask: 0xFFE00000, name: 'Alibaba Cloud' },   // 47.96.0.0/11  (47.96-127)
  { network: 0x2FEC0000, mask: 0xFFFC0000, name: 'Alibaba Cloud' },   // 47.236.0.0/14 (47.236-239)
  { network: 0x2FF00000, mask: 0xFFFC0000, name: 'Alibaba Cloud' },   // 47.240.0.0/14 (47.240-243)
  { network: 0x2FF40000, mask: 0xFFFC0000, name: 'Alibaba Cloud' },   // 47.244.0.0/14 (47.244-247)
  { network: 0x2FF80000, mask: 0xFFF80000, name: 'Alibaba Cloud' },   // 47.248.0.0/13 (47.248-255)
  { network: 0x08D00000, mask: 0xFFF00000, name: 'Alibaba Cloud' },   // 8.208.0.0/12  (8.208-223)
  { network: 0x712C0000, mask: 0xFFFC0000, name: 'Alibaba Cloud' },   // 113.44.0.0/14 (113.44-47)
  { network: 0x015C0000, mask: 0xFFFC0000, name: 'Alibaba Cloud' },   // 1.92.0.0/14   (1.92-95)

  // Huawei Cloud (AS136907, AS55990)
  { network: 0x74CC0000, mask: 0xFFFC0000, name: 'Huawei Cloud' },    // 116.204.0.0/14 (116.204-207)
  { network: 0x77080000, mask: 0xFFF80000, name: 'Huawei Cloud' },    // 119.8.0.0/13  (119.8-15)
  { network: 0x79250000, mask: 0xFFFF0000, name: 'Huawei Cloud' },    // 121.37.0.0/16
  { network: 0x7A700000, mask: 0xFFF00000, name: 'Huawei Cloud' },    // 122.112.0.0/12 (122.112-127)
  { network: 0x72740000, mask: 0xFFFC0000, name: 'Huawei Cloud' },    // 114.116.0.0/14 (114.116-119)
  { network: 0x7C460000, mask: 0xFFFE0000, name: 'Huawei Cloud' },    // 124.70.0.0/15  (124.70-71)
  { network: 0x8B9F0000, mask: 0xFFFF0000, name: 'Huawei Cloud' },    // 139.159.0.0/16
  { network: 0x6EEE0000, mask: 0xFFFE0000, name: 'Huawei Cloud' },    // 110.238.0.0/15 (110.238-239)

  // OVH / OVHcloud (AS16276) — hosting provider, not residential
  { network: 0x334B0000, mask: 0xFFFF0000, name: 'OVH' },             // 51.75.0.0/16
  { network: 0x334D0000, mask: 0xFFFF0000, name: 'OVH' },             // 51.77.0.0/16
  { network: 0x33260000, mask: 0xFFFE0000, name: 'OVH' },             // 51.38.0.0/15  (51.38-39)
  { network: 0x335B0000, mask: 0xFFFF0000, name: 'OVH' },             // 51.91.0.0/16
  { network: 0x39810000, mask: 0xFFFF0000, name: 'OVH' },             // 57.129.0.0/16
  { network: 0x8D5E0000, mask: 0xFFFE0000, name: 'OVH' },             // 141.94.0.0/15  (141.94-95)
  { network: 0x91EF0000, mask: 0xFFFF0000, name: 'OVH' },             // 145.239.0.0/16
  { network: 0x95CA0000, mask: 0xFFFE0000, name: 'OVH' },             // 149.202.0.0/15 (149.202-203)
  { network: 0x36250000, mask: 0xFFFF0000, name: 'OVH' },             // 54.37.0.0/16
  { network: 0x33440000, mask: 0xFFFC0000, name: 'OVH' },             // 51.68.0.0/14  (51.68-71)
  { network: 0x33C30000, mask: 0xFFFF0000, name: 'OVH' },             // 51.195.0.0/16
  { network: 0x97500000, mask: 0xFFFC0000, name: 'OVH' },             // 151.80.0.0/14  (151.80-83)
  { network: 0x33530000, mask: 0xFFFF0000, name: 'OVH' },             // 51.83.0.0/16
  { network: 0x33590000, mask: 0xFFFF0000, name: 'OVH' },             // 51.89.0.0/16
  { network: 0x5B860000, mask: 0xFFFE0000, name: 'OVH' },             // 91.134.0.0/15  (91.134-135)
  { network: 0x877D0000, mask: 0xFFFF0000, name: 'OVH' },             // 135.125.0.0/16
  { network: 0xB01F0000, mask: 0xFFFF0000, name: 'OVH' },             // 176.31.0.0/16
  { network: 0x57620000, mask: 0xFFFE0000, name: 'OVH' },             // 87.98.0.0/15   (87.98-99)
];

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return 0;
  return ((parseInt(parts[0], 10) << 24) |
          (parseInt(parts[1], 10) << 16) |
          (parseInt(parts[2], 10) << 8) |
          parseInt(parts[3], 10)) >>> 0;
}

function isCloudProviderIP(ip) {
  const ipInt = ipToInt(ip);
  if (ipInt === 0) return null;

  for (const cidr of CLOUD_PROVIDER_CIDRS) {
    if (((ipInt & cidr.mask) >>> 0) === cidr.network) {
      return cidr.name;
    }
  }
  return null;
}

/**
 * Detects cloud-hosted bots using HTTP/1.1 protocol.
 * Requires X-Original-Protocol header from Traefik plugin.
 * Real browsers negotiate HTTP/2+ via TLS ALPN; HTTP/1.1 from cloud IP = bot.
 *
 * Originally only matched Windows+Chrome UAs, but the botnet evolved to use
 * Android and Mac UAs (2026-04-06). Now matches any browser-like UA.
 * No real users browse from cloud provider VMs, so this is safe.
 */
function isCloudBotnet(ip, userAgent, originalProtocol) {
  // Only works if Traefik plugin is installed and provides the header
  if (!originalProtocol) return false;

  // Only flag HTTP/1.1 connections
  if (originalProtocol !== 'HTTP/1.1') return false;

  // Flag any browser-like user agent (Mozilla/5.0 covers all real browsers)
  // Also catch empty UAs from cloud IPs (scanners/scrapers)
  if (!userAgent || userAgent.length === 0) {
    // Empty UA from cloud IP = scanner
    return isCloudProviderIP(ip);
  }

  if (!/Mozilla\/5\.0/.test(userAgent)) return false;

  // Must be from a known cloud provider
  return isCloudProviderIP(ip);
}

// =============================================================================
// HTTP/1.1 BROWSER DETECTION (residential proxy botnet)
// Real browsers ALWAYS negotiate HTTP/2+ via TLS ALPN since 2015.
// Any HTTP/1.1 connection with a Chrome/Firefox/Safari UA = bot using
// residential proxies, Python requests, Go net/http, curl, etc.
// Whitelisted bots (Googlebot, Bingbot, etc.) are checked BEFORE this.
// =============================================================================

const HTTP1_BROWSER_PATTERN = /Chrome\/\d+\.|Firefox\/\d+\./;

function isHTTP1Browser(userAgent, originalProtocol) {
  if (!originalProtocol || originalProtocol !== 'HTTP/1.1') return false;
  if (!userAgent) return false;
  return HTTP1_BROWSER_PATTERN.test(userAgent);
}

// =============================================================================
// GEOIP (DB-IP lite: country + ASN, IPv4)
//
// The binary range files are produced at IMAGE BUILD time by
// scripts/build-geodb.mjs from the free DB-IP "IP to Country Lite" and "IP to
// ASN Lite" databases (CC BY 4.0 — attribution kept in README; refreshed by
// the monthly scheduled CI rebuild). Zero runtime dependencies: fixed-size
// records binary-searched directly in the loaded Buffer.
//
// Missing/corrupt files DEGRADE GRACEFULLY: lookups return null, the geo/ASN
// risk signals contribute 0, everything else keeps working. Never fail closed
// on a data file.
//
// Formats (must match scripts/build-geodb.mjs):
//   country.bin  9-byte records [u32BE start][u32BE end][u8 countryIdx]
//   asn.bin     10-byte records [u32BE start][u32BE end][u16BE orgIdx]
//                orgIdx 0xFFFF = not a datacenter org (kept for range lookup)
//   meta.json   { countries: ["CZ", ...], dcOrgs: ["Amazon...", ...] }
// =============================================================================

const GEODB_DIR = process.env.GEODB_DIR || path.join(__dirname, 'geodb');

const geoDb = {
  countryBuf: null, asnBuf: null, crawlerAsnBuf: null,
  countries: [], dcOrgs: [], crawlerAsns: [],
};

function initGeoDb(dir) {
  geoDb.countryBuf = null;
  geoDb.asnBuf = null;
  geoDb.crawlerAsnBuf = null;
  geoDb.relayBuf = null;
  geoDb.countries = [];
  geoDb.dcOrgs = [];
  geoDb.crawlerAsns = [];
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
    geoDb.countries = meta.countries || [];
    geoDb.dcOrgs = meta.dcOrgs || [];
    geoDb.countryBuf = fs.readFileSync(path.join(dir, 'country.bin'));
    geoDb.asnBuf = fs.readFileSync(path.join(dir, 'asn.bin'));
    console.log(`[GEODB] Loaded ${geoDb.countryBuf.length / 9} country ranges, `
      + `${geoDb.asnBuf.length / 10} ASN ranges (built ${meta.built || 'unknown'})`);
  } catch (err) {
    geoDb.countryBuf = null;
    geoDb.asnBuf = null;
    console.log(`[GEODB] Not available (${err.message}) — geo/ASN risk signals disabled`);
    return false;
  }

  // Optional and independently fail-open: an image built before this file
  // existed (or a build where RIPEstat was down) must still start, with the
  // ASN-verified crawlers falling back to their capped UA-only whitelist.
  try {
    geoDb.crawlerAsns = JSON.parse(
      fs.readFileSync(path.join(dir, 'meta.json'), 'utf8')).crawlerAsns || [];
    geoDb.crawlerAsnBuf = fs.readFileSync(path.join(dir, 'crawler-asn.bin'));
    console.log(`[GEODB] Loaded ${geoDb.crawlerAsnBuf.length / 10} crawler-ASN ranges `
      + `(AS${geoDb.crawlerAsns.join(', AS') || 'none'})`);
  } catch (err) {
    geoDb.crawlerAsnBuf = null;
    geoDb.crawlerAsns = [];
    console.log(`[GEODB] Crawler-ASN ranges not available (${err.message}) — `
      + 'ASN-verified crawlers fall back to capped UA-only whitelist');
  }

  // Optional, fail-open: without it Private Relay users count as hosting
  // (short pass, no GA) exactly as before the list existed.
  try {
    geoDb.relayBuf = fs.readFileSync(path.join(dir, 'apple-relay.bin'));
    console.log(`[GEODB] Loaded ${geoDb.relayBuf.length / 8} Apple Private Relay ranges`);
  } catch (err) {
    geoDb.relayBuf = null;
    console.log(`[GEODB] Apple Private Relay ranges not available (${err.message})`);
  }
  return true;
}

// Binary search over sorted fixed-size records; returns record offset or -1.
function geoRangeLookup(buf, recSize, ipInt) {
  if (!buf) return -1;
  let lo = 0;
  let hi = buf.length / recSize - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const off = mid * recSize;
    const start = buf.readUInt32BE(off);
    if (ipInt < start) {
      hi = mid - 1;
    } else if (ipInt > buf.readUInt32BE(off + 4)) {
      lo = mid + 1;
    } else {
      return off;
    }
  }
  return -1;
}

function geoCountry(ip) {
  const ipInt = ipToInt(ip);
  if (ipInt === 0) return null;
  const off = geoRangeLookup(geoDb.countryBuf, 9, ipInt);
  if (off === -1) return null;
  return geoDb.countries[geoDb.countryBuf.readUInt8(off + 8)] || null;
}

// Returns the datacenter org name when the IP's ASN classified as
// hosting/cloud at build time, else null (residential/unknown).
function asnDatacenterOrg(ip) {
  const ipInt = ipToInt(ip);
  if (ipInt === 0) return null;
  const off = geoRangeLookup(geoDb.asnBuf, 10, ipInt);
  if (off === -1) return null;
  const orgIdx = geoDb.asnBuf.readUInt16BE(off + 8);
  if (orgIdx === 0xFFFF) return null;
  return geoDb.dcOrgs[orgIdx] || null;
}

// Verified-crawler ASN membership (see build-geodb.mjs → CRAWLER_ASNS).
// Returns the ASN number announcing this IPv4 address, or null.
//   null + loaded buffer  => the IP is genuinely NOT in the ASN (impostor)
//   null + absent buffer  => we simply do not know; callers must fail OPEN
function crawlerAsn(ip) {
  const ipInt = ipToInt(ip);
  if (ipInt === 0) return null;
  const off = geoRangeLookup(geoDb.crawlerAsnBuf, 10, ipInt);
  if (off === -1) return null;
  return geoDb.crawlerAsns[geoDb.crawlerAsnBuf.readUInt16BE(off + 8)] ?? null;
}

function crawlerAsnDataLoaded() {
  return Boolean(geoDb.crawlerAsnBuf && geoDb.crawlerAsnBuf.length > 0);
}

// =============================================================================
// RISK SCORING (the "intelligent" ladder — D50)
//
// Computed ONLY for the scorable surface: anonymous GET requests that would
// render HTML (no trust cookie, no pass cookie, not a verified crawler, not
// static, not /api). Each signal is weak alone; the sum crossing
// SCORE_THRESHOLD serves the existing Turnstile challenge (managed mode:
// invisible to genuine browsers, a wall to headless fleets) — NEVER a hard
// block. The repo's history is explicit that aggregate heuristics
// misidentify humans (see the removed UA-velocity/version-span rules): every
// action here is recoverable by proving humanity once.
//
// The 2026-07/08 residential-proxy swarm this is built against: 15 309 IPs
// in 3.4 days, 89% seen on a single day only (per-IP counters structurally
// useless), flawless modern Chrome UAs over h2/h3, crawling the non-default
// locale catalog, executing GA (the analytics-pollution motive). What it
// cannot fake cheaply: coherent Chromium header sets from non-browser
// stacks, residential geography matched to audience, cookie persistence,
// and — under pressure — the Turnstile solve per fresh exit IP.
// =============================================================================

const SCORE_WEIGHTS = {
  dc_asn: 40,                  // hosting/cloud ASN (GeoDB) — no real users browse from VMs
  dc_cidr: 40,                 // curated CLOUD_PROVIDER_CIDRS fallback (works without GeoDB)
  high_risk_country: 25,       // audience prior (HIGH_RISK_COUNTRIES)
  no_sec_fetch: 40,            // claims Chrome >=80 but no Sec-Fetch-* — impossible for real Chrome
  no_sec_ch_ua: 30,            // claims Chrome >=90 but no sec-ch-ua — ditto
  platform_mismatch: 40,       // sec-ch-ua-platform contradicts the UA's OS
  no_accept_language: 20,      // browser-like UA without Accept-Language
  locale_lang_mismatch: 15,    // reads /ja/ but Accept-Language has no ja
  cookieless_deep_direct: 10,  // cookieless, referer-less entry straight to deep content
  // D101 (2026-11-16) — both only for a COOKIELESS request (a returning visitor
  // has cookies, a logged-in one is trusted before the ladder). Measured on the
  // day's allow samples: the never-challenged swarm loading GA (residential
  // IPs, "Mac Chrome", direct deep links to unprefixed Czech URLs) vs logged-in
  // users: desktop Chrome < stable-9 in 95% vs 12%; unprefixed Czech URL with
  // a browser language without cs/sk in 117/117 vs 10/15.
  stale_browser: 20,           // desktop Chrome far behind the current stable
  // D102 (2026-11-17): the solver fleet's own OS. "X11; Linux" desktop on a
  // cookieless direct deep link: 1 of 466 logged-in samples vs 13 of 14
  // never-challenged GA-loaders that hour. +10 alone never challenges
  // (10+10 = 20 x 2.5 = 50); it takes a second signal.
  linux_desktop_cookieless: 10,
  default_locale_lang_mismatch: 10, // unprefixed (Czech) deep URL, Accept-Language has no cs/sk.
                               // 10, not 15: with cookieless_deep_direct alone (20 x 2.5 = 50)
                               // a foreigner opening a shared Czech link is never challenged;
                               // it takes stale_browser too.
  pass_exhausted: 25,          // HOSTING exit whose pass budget ran out (D96): with dc_asn = 65,
                               // a re-challenge at any pressure. Never added for residential
                               // IPs — live pressure is >=1.5 most of the time, so 25 x 2.4
                               // would re-challenge heavy human readers.
};

// REMOVED 2026-08-05: `cookieless_same_origin` (was 25). Measured against 48h of
// live enforcement it was INVERTED — it fired on 33.9% of challenges that a
// human then solved, but only 0.5% of all other challenges, i.e. it was ~68x
// more likely on a human than on a bot. The reason is structural: it required
// `sec-fetch-site: same-origin` WITHOUT a cookie, which is what a real browser
// sends on a first in-site navigation (new visitor, private window, or cookies
// blocked) — while the headless fleets mostly send no Sec-Fetch-* at all and so
// trip `no_sec_fetch` instead. Replaying every scored request without it:
// 104 of 391 human challenge events relieved (27%) for 1 446 of 368 351
// non-human ones (0.39%). Do not reintroduce it as a negative "human credit"
// either — `sec-fetch-site` is trivially forgeable, so that would hand every
// scraper a free discount.

// UA OS family <-> sec-ch-ua-platform values (both sides normalized).
function uaOsFamily(ua) {
  if (/Windows NT/.test(ua)) return 'Windows';
  if (/Android/.test(ua)) return 'Android';
  if (/iPhone|iPad/.test(ua)) return 'iOS';
  if (/CrOS/.test(ua)) return 'Chrome OS';
  if (/Mac OS X/.test(ua)) return 'macOS';
  if (/Linux|X11/.test(ua)) return 'Linux';
  return null;
}

// Sliding 5-minute pressure window over scorable requests. Minute buckets;
// surgeTick() is called once per scorable request and returns the 5-min sum.
const surgeBuckets = new Array(5).fill(0);
let surgeMinute = Math.floor(Date.now() / 60000);

function rotateSurge() {
  const minute = Math.floor(Date.now() / 60000);
  if (minute !== surgeMinute) {
    const gap = Math.min(5, minute - surgeMinute);
    for (let i = 1; i <= gap; i++) {
      surgeBuckets[(surgeMinute + i) % 5] = 0;
    }
    surgeMinute = minute;
  }
  return minute;
}

function surgeTick() {
  const minute = rotateSurge();
  surgeBuckets[minute % 5]++;
  return surgeBuckets.reduce((a, b) => a + b, 0);
}

// Current 5-min sum WITHOUT counting a request: over-budget pass holders and
// allow sampling read the pressure but must not inflate it.
function surgePeek() {
  rotateSurge();
  return surgeBuckets.reduce((a, b) => a + b, 0);
}

/**
 * Is this request part of the scorable surface? HTML-rendering anonymous GETs
 * only — POSTs (webhooks, forms), API paths, health checks and non-HTML
 * Accept headers are never challenged by the ladder.
 */
function isScorableRequest(headers, requestPath) {
  const method = (headers['x-forwarded-method'] || 'GET').toUpperCase();
  if (method !== 'GET') return false;
  if (requestPath.startsWith('/api/')) return false;
  if (requestPath.startsWith('/internal-api/')) return false;
  if (requestPath.startsWith('/webhook')) return false;
  if (requestPath.startsWith('/-/')) return false;
  if (requestPath.startsWith('/.well-known/')) return false;
  // Sitemaps (D98): an unverifiable engine (Brave) must never meet a challenge
  // on the URL lists that drive indexing; they are public and cacheable anyway.
  if (/^\/sitemap[^/]*\.xml(\?|$)/.test(requestPath)) return false;
  const accept = headers['accept'] || '';
  if (accept && !accept.includes('text/html') && !accept.includes('*/*')) return false;
  return true;
}

// Paths that legitimately answer non-HTML to GETs (D98). A GET elsewhere whose
// Accept lacks text/html and */* skips the ladder today — logged as
// `would_score` (rule non_html_accept) when the shadow score would challenge.
const NON_HTML_PATH = /^\/(?:api\/|internal-api\/|webhook|-\/|\.well-known\/|_components\/|_wdt\/|sitemap|build\/|media\/|result-image\/)/;

function isAcceptBypass(headers, requestPath) {
  const method = (headers['x-forwarded-method'] || 'GET').toUpperCase();
  if (method !== 'GET') return false;
  if (NON_HTML_PATH.test(requestPath)) return false;
  const accept = headers['accept'] || '';
  return Boolean(accept) && !accept.includes('text/html') && !accept.includes('*/*');
}

// Current Chrome stable is ESTIMATED from the calendar: Chrome 153 shipped
// 2026-09-08 and Chrome releases every 2 weeks since. "Stale" = more than
// STALE_CHROME_LAG majors behind (default 9 ≈ 4 months: enterprise-pinned
// and long-unrestarted browsers stay inside it). STALE_CHROME_MIN_MAJOR pins
// the cutoff by hand if Google changes the cadence.
const STALE_CHROME_LAG = positiveIntEnv('STALE_CHROME_LAG', 9);
// D105 kill switch: DIRECT_ENTRY_CHALLENGE=0 turns the direct-entry floor off.
const DIRECT_ENTRY_CHALLENGE = process.env.DIRECT_ENTRY_CHALLENGE !== '0';
function staleChromeCutoff(nowMs = Date.now()) {
  const pinned = parseInt(process.env.STALE_CHROME_MIN_MAJOR, 10);
  if (Number.isFinite(pinned) && pinned > 0) return pinned;
  const est = 153 + Math.floor((nowMs - Date.UTC(2026, 8, 8)) / (14 * 24 * 3600 * 1000));
  return est - STALE_CHROME_LAG;
}
// Chromium-based browsers whose Chrome/ token legitimately lags (Samsung
// Internet, Opera, Yandex, UC, Vivaldi...) and every mobile UA are never
// "stale": the signal is for desktop Chrome/Edge claims only.
const STALE_EXEMPT_UA = /SamsungBrowser|OPR\/|OPiOS|YaBrowser|UCBrowser|Vivaldi|Electron|HuaweiBrowser|MiuiBrowser|CriOS|Android|Mobile/;
const DESKTOP_UA = /Windows NT|Macintosh|X11; Linux|CrOS/;

// D104 (2026-11-17): desktop Firefox too. The swarm moved from stale Chrome to
// Firefox 151 within hours of D103; logged-in Firefox users run 158-160.
// Firefox ships every 4 weeks; 160 is the anchor on 2026-11-10. Stale = more
// than STALE_FIREFOX_LAG (5) majors behind, except the ESR lines enterprises
// and Tor Browser pin (STALE_FIREFOX_ESR, default 115,128,140,153).
const STALE_FIREFOX_LAG = positiveIntEnv('STALE_FIREFOX_LAG', 5);
const STALE_FIREFOX_ESR = new Set(String(process.env.STALE_FIREFOX_ESR || '115,128,140,153')
  .split(',').map((v) => parseInt(v, 10)).filter(Number.isFinite));
function staleFirefoxCutoff(nowMs = Date.now()) {
  const pinned = parseInt(process.env.STALE_FIREFOX_MIN_MAJOR, 10);
  if (Number.isFinite(pinned) && pinned > 0) return pinned;
  const est = 160 + Math.floor((nowMs - Date.UTC(2026, 10, 10)) / (28 * 24 * 3600 * 1000));
  return est - STALE_FIREFOX_LAG;
}
function isStaleDesktopFirefox(ua) {
  const m = /Firefox\/(\d+)\./.exec(ua);
  if (!m || !DESKTOP_UA.test(ua) || /Android|Mobile|Tablet/.test(ua)) return false;
  const major = parseInt(m[1], 10);
  return major < staleFirefoxCutoff() && !STALE_FIREFOX_ESR.has(major);
}

/**
 * Pure scoring function — rate5m is passed in (tests need determinism).
 * Returns { score, base, pressure, components }.
 */
function computeRiskScore(ip, userAgent, requestPath, headers, rate5m, opts = {}) {
  const ua = userAgent || '';
  const components = {};
  if (opts.passExhausted) {
    components.pass_exhausted = SCORE_WEIGHTS.pass_exhausted;
  }

  // --- IP reputation ---------------------------------------------------------
  // iCloud Private Relay egress is exempt for Safari-family UAs only (D98).
  // D96 exempted it from hostingClass but this line kept the raw ASN check, so
  // relay users still scored dc_asn +40 (243 Safari relay IPs challenged, 42%
  // solved). Relay is Safari-only; the 636 non-Safari IPs on relay-listed
  // ranges solved 4% — they keep the score until the list is audited.
  const relayHuman = isSafariFamilyUa(ua) && isAppleRelay(ip);
  const dcOrg = relayHuman ? null : asnDatacenterOrg(ip);
  if (dcOrg) {
    components.dc_asn = SCORE_WEIGHTS.dc_asn;
  } else if (isCloudProviderIP(ip)) {
    components.dc_cidr = SCORE_WEIGHTS.dc_cidr;
  }
  const country = geoCountry(ip);
  if (country && HIGH_RISK_COUNTRIES.has(country)) {
    components.high_risk_country = SCORE_WEIGHTS.high_risk_country;
  }

  // --- Header coherence (Chromium-claimed UAs only: Safari/Firefox/CriOS
  // legitimately omit these headers, so they are never scored on them) -------
  const chromeMatch = /Chrome\/(\d+)\./.exec(ua);
  const isChromiumClaim = chromeMatch !== null && !/CriOS/.test(ua);
  const chromeMajor = isChromiumClaim ? parseInt(chromeMatch[1], 10) : 0;
  if (isChromiumClaim && chromeMajor >= 80 && !headers['sec-fetch-site']) {
    components.no_sec_fetch = SCORE_WEIGHTS.no_sec_fetch;
  }
  if (isChromiumClaim && chromeMajor >= 90 && !headers['sec-ch-ua']) {
    components.no_sec_ch_ua = SCORE_WEIGHTS.no_sec_ch_ua;
  }
  const platformHeader = (headers['sec-ch-ua-platform'] || '').replace(/"/g, '').trim();
  if (isChromiumClaim && platformHeader) {
    const uaOs = uaOsFamily(ua);
    if (uaOs && platformHeader !== uaOs) {
      components.platform_mismatch = SCORE_WEIGHTS.platform_mismatch;
    }
  }

  // --- Language / locale coherence ------------------------------------------
  const acceptLanguage = headers['accept-language'] || '';
  if (!acceptLanguage && /Mozilla\/5\.0/.test(ua)) {
    components.no_accept_language = SCORE_WEIGHTS.no_accept_language;
  }
  const locale = extractLocale(requestPath);
  if (locale && acceptLanguage && !acceptLanguage.toLowerCase().includes(locale)) {
    components.locale_lang_mismatch = SCORE_WEIGHTS.locale_lang_mismatch;
  }

  // --- Cookie persistence (the "new GA user per hit" signature) -------------
  const hasCookies = Boolean(headers['cookie']);
  if (!hasCookies && !headers['referer']
    && requestPath.split('?')[0].split('/').filter(Boolean).length >= 2) {
    components.cookieless_deep_direct = SCORE_WEIGHTS.cookieless_deep_direct;
  }

  // --- D101: the never-challenged swarm (cookieless only) -----------------
  if (!hasCookies) {
    if ((isChromiumClaim && DESKTOP_UA.test(ua) && !STALE_EXEMPT_UA.test(ua)
      && chromeMajor > 0 && chromeMajor < staleChromeCutoff()) || isStaleDesktopFirefox(ua)) {
      components.stale_browser = SCORE_WEIGHTS.stale_browser;
    }
    // D105: a typed-in / app-opened deep link with no cookie at all. Marker
    // (weight 0) — the floor below challenges it at any pressure.
    if (components.cookieless_deep_direct && headers['sec-fetch-site'] === 'none') {
      components.direct_entry = 0;
    }
    if (components.cookieless_deep_direct && /X11; Linux/.test(ua) && !/Android/.test(ua)) {
      components.linux_desktop_cookieless = SCORE_WEIGHTS.linux_desktop_cookieless;
    }
    const bare = requestPath.split('?')[0];
    if (!locale && bare.split('/').filter(Boolean).length >= 2 && acceptLanguage
      && !/(^|[\s,;])(cs|sk)(-|;|,|$)/i.test(acceptLanguage)) {
      components.default_locale_lang_mismatch = SCORE_WEIGHTS.default_locale_lang_mismatch;
    }
  }

  // --- Pressure: auto-tighten under distributed crawl -----------------------
  const pressure = rate5m / SURGE_BASELINE_5M;
  if (pressure > 2 && locale && !hasCookies) {
    components.surge_locale_cookieless = SURGE_EXTRA_SCORE;
  }

  let base = 0;
  for (const value of Object.values(components)) base += value;
  const multiplier = Math.min(2.5, Math.max(1, pressure));
  let score = Math.round(base * multiplier);

  // D103 (2026-11-17): stale desktop Chrome on a cookieless direct deep link
  // is challenged at ANY pressure. Since D101, 45 679 IPs were challenged with
  // stale_browser and 4 solved (0.009%) — the signal reaches no humans, yet at
  // night (pressure ~1.2) the swarm scored 38-58 and loaded GA.
  let floor = null;
  if (components.stale_browser && components.cookieless_deep_direct && score < SCORE_THRESHOLD) {
    score = SCORE_THRESHOLD;
    floor = 'stale_cookieless_direct';
  }
  // D105 (2026-11-17): a cookieless, referer-less direct entry onto a deep
  // page (sec-fetch-site: none) gets the managed challenge at any pressure.
  // The residential swarm is exactly this — one such hit per fresh IP, no
  // cookie ever (US/BR/PK, 91% en-US, never Portuguese from BR) — and it
  // scored 0-50 unchallenged. Returning visitors (cookies), visitors from a
  // search engine or another site (referer), in-site clicks, logged-in users
  // and verified crawlers never reach this. Watched via direct_entry's solve rate.
  if (components.direct_entry === 0 && score < SCORE_THRESHOLD && DIRECT_ENTRY_CHALLENGE) {
    score = SCORE_THRESHOLD;
    floor = floor || 'cookieless_direct_entry';
  }

  return { score, base, pressure: Math.round(pressure * 100) / 100, components, ...(floor ? { floor } : {}) };
}

// =============================================================================
// LOGGING WITH DAILY ROTATION
// =============================================================================

function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function getLogFilePath() {
  const today = new Date().toISOString().split('T')[0];
  return path.join(LOG_DIR, `blocked-${today}.log`);
}

function logBlocked(type, ip, userAgent, reason, requestPath, extra) {
  const timestamp = new Date().toISOString();
  const logEntry = { timestamp, type, ip, userAgent, reason, path: requestPath };
  if (extra) logEntry.extra = extra;  // structured payload (risk-score components)
  const logLine = JSON.stringify(logEntry) + '\n';

  console.log(`[${type.toUpperCase()}] ${ip} - ${reason} - ${userAgent.substring(0, 80)}`);

  fs.appendFile(getLogFilePath(), logLine, (err) => {
    if (err) console.error('Failed to write log:', err.message);
  });
}

// =============================================================================
// DAILY SUMMARY GENERATION
// =============================================================================

// Reason strings embed per-request numbers ("Risk score 117 (base 50 x pressure
// 2.33)", "Tencent Cloud botnet range (43.172.0.0/15)"). Keying the histogram on
// the raw string therefore produced ONE BUCKET PER REQUEST — that is what made
// summary-2026-08-02.txt 425 KB instead of ~1.5 KB. Collapse every run of digits
// so the cardinality is bounded by the number of distinct rule texts.
function summaryReasonKey(reason) {
  return String(reason || '(none)').replace(/\d+/g, 'N').slice(0, 120);
}

// Hard ceiling on the per-IP table. 145k unique IPs/day is normal under the
// swarm; the cap only bites in an extreme and we say so in the output rather
// than silently truncating.
const SUMMARY_MAX_IPS = 250000;

async function generateDailySummary() {
  const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
  const logFile = path.join(LOG_DIR, `blocked-${yesterday}.log`);

  if (!fs.existsSync(logFile)) {
    console.log(`[SUMMARY] No log file for ${yesterday}`);
    return;
  }

  try {
    // STREAMED, never readFileSync: with enforcement on, a day's log is
    // 120-170 MB, and slurping it (Buffer + UTF-8 string + split array) blew
    // past the container's memory limit. The process was OOM-killed at 00:05
    // UTC on 2026-08-04 and 2026-08-05, losing every in-memory counter
    // (permabans, rate limits, rDNS cache) and producing no summary at all.
    const stats = { total: 0, malformed: 0, byType: {}, byReason: {} };
    const topIPs = new Map();
    let ipsPruned = false;

    const rl = readline.createInterface({
      input: fs.createReadStream(logFile, { encoding: 'utf8' }),
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      if (!line) continue;
      let entry;
      try {
        entry = JSON.parse(line);
      } catch (e) {
        stats.malformed++;
        continue;
      }
      if (entry.type === 'allow_sample') {
        // Allowed traffic (ALLOW_SAMPLE_RATE sample) — not a block; counted apart.
        stats.allowSampled = (stats.allowSampled || 0) + 1;
        continue;
      }
      stats.total++;
      stats.byType[entry.type] = (stats.byType[entry.type] || 0) + 1;
      const rk = summaryReasonKey(entry.reason);
      stats.byReason[rk] = (stats.byReason[rk] || 0) + 1;
      const ip = entry.ip || '(none)';
      topIPs.set(ip, (topIPs.get(ip) || 0) + 1);
      if (topIPs.size > SUMMARY_MAX_IPS) {
        // Drop the singletons: an IP seen once cannot reach a top-10 whose
        // entries are in the hundreds. Bounds memory without a second pass.
        for (const [k, v] of topIPs) if (v === 1) topIPs.delete(k);
        ipsPruned = true;
      }
    }

    const top = [...topIPs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const byCount = obj => Object.entries(obj).sort((a, b) => b[1] - a[1]);

    const summary = `Daily Block Summary: ${yesterday}
================================

Total Blocked Requests: ${stats.total}${stats.malformed ? `
Malformed log lines skipped: ${stats.malformed}` : ''}${stats.allowSampled ? `
Allowed requests sampled (allow_sample, not counted above): ${stats.allowSampled}` : ''}

By Type:
${byCount(stats.byType).map(([k, v]) => `  ${k}: ${v}`).join('\n')}

By Reason (digits collapsed to N):
${byCount(stats.byReason).slice(0, 40).map(([k, v]) => `  ${k}: ${v}`).join('\n')}

Top 10 Blocked IPs:${ipsPruned ? '  (single-hit IPs pruned above '
  + `${SUMMARY_MAX_IPS} distinct)` : ''}
${top.map(([ip, count]) => `  ${ip}: ${count}`).join('\n')}
`;

    fs.writeFileSync(path.join(LOG_DIR, `summary-${yesterday}.txt`), summary);
    console.log(`[SUMMARY] Generated for ${yesterday}: ${stats.total} blocks`);
  } catch (err) {
    console.error(`[SUMMARY] Failed: ${err.message}`);
  }
}

// Removes `blocked-YYYY-MM-DD.log` files older than the retention window.
// The cutoff uses the date IN THE FILE NAME (UTC, the clock getLogFilePath()
// writes with), not mtime, so a copied or restored volume ages correctly.
// Async unlinks: the first run on an old volume frees gigabytes, and a sync
// loop would stall every forwardAuth answer while it runs.
async function pruneOldBlockLogs(now = Date.now(), retentionDays = LOG_RETENTION_DAYS) {
  if (!retentionDays) return [];
  const cutoff = new Date(now - retentionDays * 86400000).toISOString().split('T')[0];
  let names;
  try {
    names = await fs.promises.readdir(LOG_DIR);
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  const removed = [];
  for (const name of names) {
    const match = /^blocked-(\d{4}-\d{2}-\d{2})\.log$/.exec(name);
    if (!match || match[1] >= cutoff) continue;
    try {
      await fs.promises.unlink(path.join(LOG_DIR, name));
      removed.push(name);
    } catch (err) {
      console.error(`[RETENTION] ${name}: ${err.message}`);
    }
  }
  if (removed.length) {
    console.log(`[RETENTION] Removed ${removed.length} block log(s) older than ${retentionDays} days`);
  }
  return removed;
}

function scheduleNextSummary() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(0, 5, 0, 0);

  const msUntilSummary = tomorrow - now;

  // generateDailySummary is async now; an unhandled rejection here would take
  // the whole process down on Node >=15, which is exactly the daily outage this
  // change exists to remove. Swallow at the boundary — it already logs.
  // Prune AFTER the summary, so yesterday's file is always summarised first.
  const run = () => {
    generateDailySummary()
      .catch(err => console.error(`[SUMMARY] ${err.message}`))
      .then(() => pruneOldBlockLogs())
      .catch(err => console.error(`[RETENTION] ${err.message}`));
  };

  setTimeout(() => {
    run();
    setInterval(run, 24 * 60 * 60 * 1000);
  }, msUntilSummary);

  console.log(`[SUMMARY] Scheduled in ${Math.round(msUntilSummary / 1000 / 60)} minutes`);
}

// =============================================================================
// RATE LIMITING
// =============================================================================

const requests = new Map();

// =============================================================================
// PERMANENT BAN TRACKING
// =============================================================================

const bannedIPs = new Map();  // ip -> { bannedAt, reason, locales }

function loadBannedIPs() {
  try {
    if (fs.existsSync(BANNED_IPS_FILE)) {
      const data = JSON.parse(fs.readFileSync(BANNED_IPS_FILE, 'utf8'));
      const now = Date.now();

      for (const [ip, info] of Object.entries(data)) {
        const bannedAt = new Date(info.bannedAt).getTime();
        // Skip expired bans
        if (now - bannedAt < BAN_DURATION) {
          bannedIPs.set(ip, info);
        }
      }
      console.log(`[BAN] Loaded ${bannedIPs.size} active bans from file`);
    }
  } catch (err) {
    console.error('[BAN] Failed to load banned IPs:', err.message);
  }
}

// Coalesced async write (D98): a burst of bans used to do one synchronous
// pretty-printed JSON write per ban on the request path.
let banSaveScheduled = false;
function saveBannedIPs() {
  if (banSaveScheduled) return;
  banSaveScheduled = true;
  setTimeout(() => {
    banSaveScheduled = false;
    let json;
    try {
      json = JSON.stringify(Object.fromEntries(bannedIPs));
    } catch (err) {
      console.error('[BAN] Failed to serialise banned IPs:', err.message);
      return;
    }
    fs.writeFile(BANNED_IPS_FILE, json, (err) => {
      if (err) console.error('[BAN] Failed to save banned IPs:', err.message);
    });
  }, 1000).unref();
}

function banIP(ip, reason, locales) {
  const info = {
    bannedAt: new Date().toISOString(),
    reason,
    locales: Array.from(locales)
  };
  bannedIPs.set(ip, info);
  saveBannedIPs();
  console.log(`[BAN] Permanently banned ${ip}: ${reason}`);
}

function isPermanentlyBanned(ip) {
  if (!bannedIPs.has(ip)) return false;

  const info = bannedIPs.get(ip);
  const bannedAt = new Date(info.bannedAt).getTime();

  // Check if ban has expired
  if (Date.now() - bannedAt >= BAN_DURATION) {
    bannedIPs.delete(ip);
    saveBannedIPs();
    console.log(`[BAN] Ban expired for ${ip}`);
    return false;
  }

  return true;
}

// =============================================================================
// LOCALE SWITCHING DETECTION
// =============================================================================

const localeTracker = new Map();  // ip -> { localeCounts: Map<locale, count>, windowStart }

function extractLocale(requestPath) {
  const match = requestPath.match(/^\/(en|de|fr|es|ja)\//i);
  return match ? match[1].toLowerCase() : null;
}

function checkLocaleSwitch(ip, requestPath) {
  const locale = extractLocale(requestPath);
  if (!locale) return false;  // Not a locale path

  const now = Date.now();

  if (!localeTracker.has(ip)) {
    const localeCounts = new Map();
    localeCounts.set(locale, 1);
    localeTracker.set(ip, { localeCounts, windowStart: now });
    capMap(localeTracker, MAX_MAP_ENTRIES);
    return false;
  }

  const record = localeTracker.get(ip);

  // Reset window if expired
  if (now - record.windowStart > LOCALE_WINDOW) {
    record.localeCounts = new Map([[locale, 1]]);
    record.windowStart = now;
    return false;
  }

  // Increment count for this locale
  const currentCount = record.localeCounts.get(locale) || 0;
  record.localeCounts.set(locale, currentCount + 1);

  // Count locales with LOCALE_MIN_HITS+ hits
  const qualifyingLocales = [];
  for (const [loc, count] of record.localeCounts) {
    if (count >= LOCALE_MIN_HITS) {
      qualifyingLocales.push(loc);
    }
  }

  // Check threshold: LOCALE_THRESHOLD+ locales each with LOCALE_MIN_HITS+ requests
  if (qualifyingLocales.length >= LOCALE_THRESHOLD) {
    const elapsed = Math.round((now - record.windowStart) / 1000);
    const details = qualifyingLocales.map(loc =>
      `${loc}(${record.localeCounts.get(loc)})`
    ).join(', ');
    const reason = `Locale scraping detected: ${details} in ${elapsed}s`;
    banIP(ip, reason, qualifyingLocales);
    localeTracker.delete(ip);
    return true;  // Trigger ban
  }

  return false;
}

// =============================================================================
// PAGE SCRAPING DETECTION (puzzle/profile pages)
// =============================================================================

const PUZZLE_PAGE_PATTERN = /^\/((?:en|es|fr|de|ja)\/)?(?:puzzle|skladam-puzzle|solving-puzzle|resolviendo-puzzle|パズル解決中|パズル|resoudre-puzzle|puzzle-loesen)\/([^\/?#]+)/;
const PROFILE_PAGE_PATTERN = /^\/((?:en|es|fr|de|ja)\/)?(?:profil-hrace|player-profile|perfil-jugador|プレイヤー-プロフィール|profil-joueur|spieler-profil)\/([^\/?#]+)/;

const puzzleScrapeTracker = new Map();   // "ip|ua" -> { uniqueIds: Set, windowStart }
const profileScrapeTracker = new Map();  // "ip|ua" -> { uniqueIds: Set, windowStart }
const scrapeStrikes = new Map();         // ip -> [timestamp, ...]

function extractPuzzleId(requestPath) {
  const match = requestPath.match(PUZZLE_PAGE_PATTERN);
  return match ? match[2] : null;
}

function extractProfileId(requestPath) {
  const match = requestPath.match(PROFILE_PAGE_PATTERN);
  return match ? match[2] : null;
}

function recordScrapeStrike(ip, reason) {
  const now = Date.now();
  const strikes = scrapeStrikes.get(ip) || [];

  // Filter to strikes within the strike window (24h)
  const recentStrikes = strikes.filter(ts => now - ts < SCRAPE_STRIKE_WINDOW);
  recentStrikes.push(now);
  scrapeStrikes.set(ip, recentStrikes);
  capMap(scrapeStrikes, MAX_MAP_ENTRIES);

  if (recentStrikes.length >= SCRAPE_STRIKES_FOR_BAN) {
    banIP(ip, reason, []);
    return { banned: true, strikes: recentStrikes.length, reason };
  }

  return { banned: false, strikes: recentStrikes.length, reason };
}

function checkScrapeTracker(tracker, threshold, window, ip, userAgent, pageId, pageType) {
  const key = ip + '|' + userAgent;
  const now = Date.now();

  if (!tracker.has(key)) {
    const uniqueIds = new Set([pageId]);
    tracker.set(key, { uniqueIds, windowStart: now });
    capMap(tracker, MAX_MAP_ENTRIES);
    return null;
  }

  const record = tracker.get(key);

  // Reset window if expired
  if (now - record.windowStart > window) {
    record.uniqueIds = new Set([pageId]);
    record.windowStart = now;
    return null;
  }

  record.uniqueIds.add(pageId);

  if (record.uniqueIds.size >= threshold) {
    const elapsed = Math.round((now - record.windowStart) / 1000);
    const reason = `${pageType} scraping detected: ${record.uniqueIds.size} unique pages in ${elapsed}s`;
    // Reset tracker so next window can trigger a new strike (keep triggering ID)
    record.uniqueIds = new Set([pageId]);
    record.windowStart = now;
    return recordScrapeStrike(ip, reason);
  }

  return null;
}

/**
 * Checks if request is part of systematic page scraping.
 * Returns { banned, strikes, reason } if threshold exceeded, null otherwise.
 */
function checkPageScraping(ip, userAgent, requestPath) {
  const puzzleId = extractPuzzleId(requestPath);
  if (puzzleId) {
    return checkScrapeTracker(
      puzzleScrapeTracker, PUZZLE_SCRAPE_THRESHOLD, PUZZLE_SCRAPE_WINDOW,
      ip, userAgent, puzzleId, 'Puzzle'
    );
  }

  const profileId = extractProfileId(requestPath);
  if (profileId) {
    return checkScrapeTracker(
      profileScrapeTracker, PROFILE_SCRAPE_THRESHOLD, PROFILE_SCRAPE_WINDOW,
      ip, userAgent, profileId, 'Profile'
    );
  }

  return null;
}

// =============================================================================
// RATE LIMITING
// =============================================================================

function isRateLimited(ip, userAgent) {
  const key = ip + '|' + userAgent;
  const now = Date.now();

  if (!requests.has(key)) {
    requests.set(key, { count: 1, windowStart: now });
    capMap(requests, MAX_MAP_ENTRIES);
    return false;
  }

  const record = requests.get(key);

  if (now - record.windowStart > RATE_WINDOW) {
    record.count = 1;
    record.windowStart = now;
    return false;
  }

  record.count++;
  return record.count > RATE_LIMIT;
}

// Cleanup old records every 5 minutes
setInterval(() => {
  const now = Date.now();

  // Expired passes no longer need their page counters
  for (const [key, rec] of passPages) {
    if (now > rec.expiresMs) passPages.delete(key);
  }

  // Clean rate limit records
  for (const [key, record] of requests) {
    if (now - record.windowStart > RATE_WINDOW * 2) {
      requests.delete(key);
    }
  }

  // Clean locale tracker records
  for (const [key, record] of localeTracker) {
    if (now - record.windowStart > LOCALE_WINDOW * 2) {
      localeTracker.delete(key);
    }
  }


  // Clean page scraping trackers
  for (const [key, record] of puzzleScrapeTracker) {
    if (now - record.windowStart > PUZZLE_SCRAPE_WINDOW * 2) {
      puzzleScrapeTracker.delete(key);
    }
  }
  for (const [key, record] of profileScrapeTracker) {
    if (now - record.windowStart > PROFILE_SCRAPE_WINDOW * 2) {
      profileScrapeTracker.delete(key);
    }
  }

  // Clean expired scrape strikes
  for (const [ip, strikes] of scrapeStrikes) {
    const recent = strikes.filter(ts => now - ts < SCRAPE_STRIKE_WINDOW);
    if (recent.length === 0) {
      scrapeStrikes.delete(ip);
    } else {
      scrapeStrikes.set(ip, recent);
    }
  }

  // Clean challenge verify-attempt records
  for (const [ip, record] of verifyAttempts) {
    if (now - record.windowStart > 120000) {
      verifyAttempts.delete(ip);
    }
  }

  // Clean expired rDNS verdicts and whitelisted-crawler buckets
  for (const [ip, record] of rdnsCache) {
    if (record.exp <= now) {
      rdnsCache.delete(ip);
    }
  }
  for (const [key, record] of crawlerBuckets) {
    if (now - record.windowStart > 120000) {
      crawlerBuckets.delete(key);
    }
  }

}, 5 * 60 * 1000).unref(); // unref: don't hold the process open (tests require this module)

// =============================================================================
// HUMAN-RECOVERY CHALLENGE (Cloudflare Turnstile)
//
// Flow (forwardAuth constraints baked in — Traefik forwards request HEADERS
// only, never bodies, and returns our full response to the client on non-2xx):
//   1. A challenge-eligible rule serves the 403 challenge page at the ORIGINAL
//      URL (forwardAuth renders our body at the URL the user requested).
//   2. The solved widget reloads the same URL with ?__bb_token=<token> —
//      query string because it survives in X-Forwarded-Uri; a POST body would
//      never reach us.
//   3. We verify the token with siteverify, reply 302 + Set-Cookie (works on
//      the deny path) back to the clean URL, and lift any permaban for the IP.
//   4. The cookie arrives in forwarded headers on every later request and
//      bypasses ONLY the challenge-eligible heuristics — never rate limits,
//      never scrape detection, never the hard rules.
//
// Cookie format: "<expiresMs>.<hmac>" where hmac = HMAC-SHA256(secret,
// "<ip>|<expiresMs>"). IP-bound: a shared/stolen cookie is worthless from
// another address, and a rotating proxy pool has to solve per exit IP.
// =============================================================================

function signPassCookie(ip, expiresMs) {
  return crypto.createHmac('sha256', CHALLENGE_COOKIE_SECRET)
    .update(`${ip}|${expiresMs}`)
    .digest('hex');
}

// Hosting class: datacenter / ISP-proxy ASN (GeoDB, build-geodb.mjs) or a
// curated cloud CIDR. Returns the network name, or null (residential/unknown).
function hostingClass(ip) {
  if (!ip) return null;
  // iCloud Private Relay egress is people in Safari, not crawlers, even though
  // it leaves through Cloudflare/Akamai (datacenter by keyword).
  if (isAppleRelay(ip)) return null;
  return asnDatacenterOrg(ip) || isCloudProviderIP(ip) || null;
}

// Safari / iOS WebKit, excluding the Chromium/Firefox/Edge/Opera wrappers and
// the Apple link-preview fetcher (which carries a 2015 Safari token).
function isSafariFamilyUa(ua) {
  if (!ua || !/AppleWebKit\//.test(ua) || !/(Version\/[\d.]+.*Safari\/|Mobile\/\w+)/.test(ua)) return false;
  return !/(Chrome|Chromium|CriOS|FxiOS|EdgiOS|Edg\/|OPR\/|OPiOS|facebookexternalhit|bot|crawl)/i.test(ua);
}

function isAppleRelay(ip) {
  const ipInt = ipToInt(ip);
  if (ipInt === 0) return false;
  return geoRangeLookup(geoDb.relayBuf, 8, ipInt) !== -1;
}

function passTtlFor(ip) {
  return hostingClass(ip) ? Math.min(HOSTING_PASS_TTL_MS, CHALLENGE_COOKIE_TTL_MS) : CHALLENGE_COOKIE_TTL_MS;
}

function makePassCookie(ip) {
  const ttlMs = passTtlFor(ip);
  const expiresMs = Date.now() + ttlMs;
  const value = `${expiresMs}.${signPassCookie(ip, expiresMs)}`;
  const maxAgeSec = Math.floor(ttlMs / 1000);
  return `${CHALLENGE_COOKIE_NAME}=${value}; Max-Age=${maxAgeSec}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

function hasValidPassCookie(cookieHeader, ip) {
  return readPassCookie(cookieHeader, ip) !== null;
}

// Validates the pass cookie; returns { key, expiresMs } or null. `key`
// identifies this one pass (IP + its signed expiry) for the page budget.
function readPassCookie(cookieHeader, ip) {
  if (!cookieHeader) return null;

  // Minimal cookie-header parse — find our cookie among the others
  let raw = null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === CHALLENGE_COOKIE_NAME) {
      raw = part.slice(eq + 1).trim();
      break;
    }
  }
  if (!raw) return null;

  const dot = raw.indexOf('.');
  if (dot === -1) return null;

  const expiresMs = parseInt(raw.slice(0, dot), 10);
  const now = Date.now();
  if (!Number.isFinite(expiresMs) || now > expiresMs) return null;
  // Longer-lived than this IP's class allows: minted under older rules.
  if (expiresMs - now > passTtlFor(ip) + PASS_TTL_SLACK_MS) return null;

  const actual = raw.slice(dot + 1);
  // Hex only, exact length — BEFORE timingSafeEqual. A JS-string length check
  // let 64 multi-byte chars through; their UTF-8 buffers differ in length, the
  // call threw, and the handler's catch-all answered 200 (D98: `/.env` came
  // back 200 with a crafted cookie). Malformed = no pass, never an error.
  if (!/^[0-9a-f]{64}$/.test(actual)) return null;
  const expected = signPassCookie(ip, expiresMs);
  if (!crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))) return null;
  return { key: `${ip}|${expiresMs}`, expiresMs };
}

// Page budget per pass (in memory: a restart refills budgets, which only ever
// errs toward the visitor). key -> { count, expiresMs, logged }.
const passPages = new Map();

// Counts one scorable page against the pass. Returns true while within
// budget; on the first page over budget logs `pass_exhausted` once.
function consumePassPage(pass, ip, userAgent, requestPath) {
  let rec = passPages.get(pass.key);
  if (!rec) {
    rec = { count: 0, expiresMs: pass.expiresMs, logged: false };
    passPages.set(pass.key, rec);
    capMap(passPages, MAX_MAP_ENTRIES);
  }
  rec.count++;
  const hosting = hostingClass(ip);
  const budget = hosting ? HOSTING_PASS_PAGE_BUDGET : PASS_PAGE_BUDGET;
  if (rec.count <= budget) return true;
  if (!rec.logged) {
    rec.logged = true;
    logBlocked('pass_exhausted', ip, userAgent,
      `Pass page budget (${budget}) used up`, requestPath, { budget, hosting: hosting || null });
  }
  return false;
}

// =============================================================================
// TRUSTED-HUMAN COOKIE (__bb_trust) — validation only, the app issues it
// =============================================================================

function getCookieValue(cookieHeader, name) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return null;
}

function b64urlDecode(value) {
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Validates the app-issued trust cookie. Returns the opaque uid (for abuse
 * telemetry — one uid fanning out over many IPs would mean a registered
 * scraper account) or null. Not IP-bound by design; see the config comment.
 */
function getTrustedUid(cookieHeader) {
  if (!TRUST_ENABLED) return null;
  const raw = getCookieValue(cookieHeader, TRUST_COOKIE_NAME);
  if (!raw) return null;

  const dot = raw.lastIndexOf('.');
  if (dot === -1) return null;

  let payload;
  let actual;
  try {
    payload = b64urlDecode(raw.slice(0, dot));
    actual = b64urlDecode(raw.slice(dot + 1));
  } catch (e) {
    return null;
  }

  const expected = crypto.createHmac('sha256', TRUST_COOKIE_SECRET).update(payload).digest();
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    return null;
  }

  const parts = payload.toString('utf8').split('|');  // bb-trust|v1|<uid>|<iatMs>
  if (parts.length !== 4 || parts[0] !== 'bb-trust' || parts[1] !== 'v1') return null;

  const issuedAt = parseInt(parts[3], 10);
  if (!Number.isFinite(issuedAt) || Date.now() > issuedAt + TRUST_COOKIE_TTL_MS) return null;
  if (parts[2] === '') return null;

  return parts[2];
}

/**
 * Builds an ABSOLUTE redirect URL for the challenge 302s.
 * Traefik resolves a relative Location against the AUTH SERVER's URL, so a
 * relative redirect would send the browser to http://myspeedpuzzling-bot-
 * blocker:3000/... (found in production verification). The public scheme and
 * host arrive in the X-Forwarded-* headers forwardAuth always sends; the
 * fallback keeps the relative URI for direct (non-Traefik) access like tests.
 */
function buildRedirectUrl(headers, cleanUri) {
  const host = headers['x-forwarded-host'];
  if (!host) return cleanUri;
  const proto = headers['x-forwarded-proto'] || 'https';
  return `${proto}://${host}${cleanUri}`;
}

/**
 * Extracts the challenge token from the forwarded URI.
 * Returns { token, cleanUri } (token param stripped, other params kept),
 * or null when no token is present.
 */
function extractChallengeToken(requestPath) {
  if (!requestPath.includes(CHALLENGE_TOKEN_PARAM)) return null;
  let url;
  try {
    url = new URL(requestPath, 'http://internal');
  } catch (e) {
    return null;
  }
  const token = url.searchParams.get(CHALLENGE_TOKEN_PARAM);
  if (!token) return null;
  url.searchParams.delete(CHALLENGE_TOKEN_PARAM);
  return { token, cleanUri: url.pathname + url.search };
}

/**
 * Server-side verification against Turnstile siteverify.
 * Tokens are single-use and expire after 5 minutes — replay is Cloudflare's
 * problem, not ours. Fails CLOSED on network errors: the user just sees the
 * challenge again and can retry.
 */
async function verifyTurnstileToken(token, ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const body = new URLSearchParams({
      secret: TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: ip,
    });
    const response = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const result = await response.json();
    return result.success === true;
  } catch (err) {
    console.error(`[CHALLENGE] siteverify error: ${err.message}`);
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

// siteverify attempts are rate-limited per IP so the verify endpoint cannot be
// used to hammer Cloudflare (or burn CPU) with garbage tokens.
const verifyAttempts = new Map();  // ip -> { count, windowStart }

function isVerifyRateLimited(ip) {
  const now = Date.now();
  const record = verifyAttempts.get(ip);
  if (!record || now - record.windowStart > 60000) {
    verifyAttempts.set(ip, { count: 1, windowStart: now });
    capMap(verifyAttempts, MAX_MAP_ENTRIES);
    return false;
  }
  record.count++;
  return record.count > CHALLENGE_VERIFY_LIMIT;
}

function logChallenge(event, ip, userAgent, detail, requestPath) {
  // Same JSONL file as blocks — the daily summary picks the new types up
  // automatically, and challenge_passed counts ARE the measured
  // false-positive rate of the challenge-eligible rules.
  logBlocked(event, ip, userAgent, detail, requestPath);
}

/**
 * Serves the challenge page (403) for a challenge-eligible block, or the
 * plain block page when the challenge is disabled. The block itself was
 * already logged by the caller with its original type/reason — behavior
 * stats stay comparable with pre-challenge history.
 */
function serveChallengeOrBlock(res, reason, headerReason, locale = 'en', ip = '') {
  if (!CHALLENGE_ENABLED) {
    const html = renderPage('blocked', { reason, locale, ip });
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': headerReason,
    });
    res.end(html);
    return;
  }
  const html = renderPage('challenge', { reason, locale, ip });
  res.writeHead(403, {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Blocked-Reason': headerReason,
    // The page must never be cached: it embeds a per-visit widget
    'Cache-Control': 'no-store',
  });
  res.end(html);
}

// =============================================================================
// HTML TEMPLATES
// =============================================================================

// -----------------------------------------------------------------------------
// Brand system (MySpeedPuzzling). These pages are the only thing a wrongly-
// caught human ever sees, so they carry the site's own look: real logo and
// Rubik webfont pulled from myspeedpuzzling.com itself. That works because the
// ASSETS router (compose.yaml, priority 100) carries neither the bot-blocker
// nor the CrowdSec bouncer — a blocked client can still fetch /img and /fonts,
// verified in production. Everything else is inline: no CDN, no build step.
// Colors are the app's SCSS variables (assets/styles/_variables.scss):
// primary #fe696a, headings #373f50, body #4b566b, gray-100 #f6f9fc.
// -----------------------------------------------------------------------------

const BRAND_CSS = `
@font-face{font-family:Rubik;font-style:normal;font-weight:300 700;font-display:swap;src:url(/fonts/rubik/rubik-latin-ext.woff2) format("woff2");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:Rubik;font-style:normal;font-weight:300 700;font-display:swap;src:url(/fonts/rubik/rubik-latin.woff2) format("woff2");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
:root{
  color-scheme:light dark;
  --brand:#fe696a; --brand-soft:rgba(254,105,106,.1);
  --ink:#373f50; --body:#4b566b; --muted:#7d879c;
  --bg:#f6f9fc; --card:#fff; --line:#e3e9ef;
}
@media (prefers-color-scheme:dark){
  :root{--ink:#f3f5f9; --body:#c8cfda; --muted:#9aa3ae; --bg:#1c2130; --card:#242b3d; --line:#333c52;}
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:Rubik,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:var(--bg); color:var(--body);
  font-size:15px; line-height:1.6;
  min-height:100vh; display:flex; align-items:center; justify-content:center;
  padding:24px 16px;
}
.card{
  background:var(--card); border-radius:14px; border:1px solid var(--line);
  box-shadow:0 18px 40px -24px rgba(55,63,80,.45);
  max-width:32rem; width:100%; padding:40px 32px 32px; text-align:center;
}
.logo{height:52px;width:auto;margin:0 auto 20px;display:block}
h1{color:var(--ink);font-size:22px;font-weight:500;line-height:1.3;margin-bottom:12px}
p{margin-bottom:16px}
.widget{display:flex;justify-content:center;min-height:66px;margin:24px 0 8px}
.login-hint{font-size:14px;margin:12px 0 0}
.login-hint a{font-weight:600;white-space:nowrap}
.foot{
  margin-top:24px;padding-top:20px;border-top:1px solid var(--line);
  font-size:13.5px;color:var(--muted);
}
a{color:var(--brand);text-decoration:none;font-weight:500}
a:hover{text-decoration:underline}
details{margin-top:16px;text-align:left}
summary{
  cursor:pointer;font-size:12.5px;color:var(--muted);text-align:center;
  list-style:none;padding:4px;
}
summary::-webkit-details-marker{display:none}
summary:hover{color:var(--brand)}
.reason{
  margin-top:10px;padding:10px 12px;border-radius:8px;background:var(--brand-soft);
  font:12px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--body);
  word-break:break-word;
}
.reason span{color:var(--muted)}
@media (max-width:420px){.card{padding:32px 20px 24px}h1{font-size:20px}}
`;

// Six locales — the site's own set. A wrongly-challenged Czech puzzler should
// not have to read an English apology. Locale comes from the URL prefix first
// (authoritative: the app's own routing), Accept-Language second.
const PAGE_STRINGS = {
  en: {
    lang: 'en',
    loginTitle: 'Please log in to continue',
    loginBody: 'On this network we show results and statistics to logged-in puzzlers only &mdash; automated scrapers keep coming from it. Log in (or create a free account) and you continue straight to this page. Just registered? Confirm your e-mail first.',
    challengeLoginHint: 'Have an account? Logged-in puzzlers are recognised automatically and never see this check.',
    challengeLoginCta: 'Log in',
    challengeTitle: 'Sorry to bother you!',
    challengeBody: 'We just need to make sure you are a real puzzler and not a bot. It takes a second &mdash; then you continue straight to the page you wanted.',
    rateTitle: 'Whoa, that was fast!',
    rateBody: 'A lot of requests arrived from your connection in a short time, so we have paused things for a minute. Please try again shortly.',
    blockedTitle: 'We stopped this request',
    blockedBody: 'Our bot protection blocked this one. If you are a real puzzler seeing this by mistake, we are sorry &mdash; write to us and we will fix it right away.',
    helpLead: 'Something not right? Email',
    helpTail: 'and we will sort it out.',
    details: 'Technical details',
    labelReason: 'Reason',
    labelIp: 'Your IP address',
  },
  cs: {
    lang: 'cs',
    loginTitle: 'Pro pokra&#269;ov&aacute;n&iacute; se pros&iacute;m p&#345;ihlas',
    loginBody: 'Z t&eacute;to s&iacute;t&#283; k n&aacute;m chod&iacute; automatick&eacute; stahov&aacute;n&iacute; dat, proto tu v&yacute;sledky a statistiky ukazujeme jen p&#345;ihl&aacute;šen&yacute;m puzzlist&#367;m. P&#345;ihlas se (nebo si zalo&#382; &uacute;&#269;et zdarma) a budeš pokra&#269;ovat rovnou na tuto str&aacute;nku. Pr&aacute;v&#283; ses registroval/a? Nejd&#345;&iacute;v potvr&#271; e-mail.',
    challengeLoginHint: 'M&aacute;š &uacute;&#269;et? P&#345;ihl&aacute;šen&eacute; puzzlisty pozn&aacute;me automaticky a tahle kontrola se jim nikdy nezobraz&iacute;.',
    challengeLoginCta: 'P&#345;ihl&aacute;sit se',
    challengeTitle: 'Omlouv&aacute;me se za zdr&#382;en&iacute;!',
    challengeBody: 'Jen se ujist&iacute;me, &#382;e jsi skute&#269;n&yacute; puzzlista a ne robot. Zabere to chvilku &mdash; pak budeš pokra&#269;ovat rovnou na str&aacute;nku, kterou chceš.',
    rateTitle: 'Hola, to bylo rychl&eacute;!',
    rateBody: 'Z tv&eacute;ho p&#345;ipojen&iacute; p&#345;išlo za kr&aacute;tkou dobu hodn&#283; po&#382;adavk&#367;, tak jsme to na chvilku pozastavili. Zkus to pros&iacute;m za minutku znovu.',
    blockedTitle: 'Tento po&#382;adavek jsme zastavili',
    blockedBody: 'Naše ochrana proti robot&#367;m tenhle po&#382;adavek zablokovala. Pokud jsi skute&#269;n&yacute; puzzlista a vid&iacute;š to omylem, mrz&iacute; n&aacute;s to &mdash; napiš n&aacute;m a hned to spravíme.',
    helpLead: 'N&#283;co nen&iacute; v po&#345;&aacute;dku? Napiš na',
    helpTail: 'a vy&#345;eš&iacute;me to.',
    details: 'Technick&eacute; detaily',
    labelReason: 'D&#367;vod',
    labelIp: 'Tvoje IP adresa',
  },
  de: {
    lang: 'de',
    loginTitle: 'Bitte melde dich an, um fortzufahren',
    loginBody: 'Aus diesem Netzwerk kommen automatisierte Scraper, deshalb zeigen wir Ergebnisse und Statistiken hier nur angemeldeten Puzzlern. Melde dich an (oder erstelle ein kostenloses Konto) und du landest direkt auf dieser Seite. Gerade registriert? Best&auml;tige zuerst deine E-Mail.',
    challengeLoginHint: 'Du hast ein Konto? Angemeldete Puzzler erkennen wir automatisch &mdash; sie sehen diese Pr&uuml;fung nie.',
    challengeLoginCta: 'Anmelden',
    challengeTitle: 'Entschuldige die St&ouml;rung!',
    challengeBody: 'Wir pr&uuml;fen nur kurz, ob du ein echter Puzzler bist und kein Bot. Das dauert einen Moment &mdash; danach geht es direkt weiter zu deiner Seite.',
    rateTitle: 'Oha, das ging schnell!',
    rateBody: 'Von deiner Verbindung kamen in kurzer Zeit sehr viele Anfragen, deshalb pausieren wir kurz. Bitte versuche es in einer Minute noch einmal.',
    blockedTitle: 'Diese Anfrage haben wir gestoppt',
    blockedBody: 'Unser Bot-Schutz hat sie blockiert. Wenn du ein echter Puzzler bist und das zu Unrecht siehst, tut es uns leid &mdash; schreib uns, wir kl&auml;ren das sofort.',
    helpLead: 'Etwas stimmt nicht? Schreib an',
    helpTail: 'und wir k&uuml;mmern uns darum.',
    details: 'Technische Details',
    labelReason: 'Grund',
    labelIp: 'Deine IP-Adresse',
  },
  es: {
    lang: 'es',
    loginTitle: 'Inicia sesi&oacute;n para continuar',
    loginBody: 'Desde esta red nos llegan scrapers autom&aacute;ticos, as&iacute; que aqu&iacute; mostramos resultados y estad&iacute;sticas solo a quien ha iniciado sesi&oacute;n. Inicia sesi&oacute;n (o crea una cuenta gratis) y seguir&aacute;s directo a esta p&aacute;gina. &iquest;Acabas de registrarte? Confirma primero tu correo.',
    challengeLoginHint: '&iquest;Tienes cuenta? Reconocemos autom&aacute;ticamente a quien ha iniciado sesi&oacute;n y nunca ve esta comprobaci&oacute;n.',
    challengeLoginCta: 'Iniciar sesi&oacute;n',
    challengeTitle: '&iexcl;Perdona la molestia!',
    challengeBody: 'Solo comprobamos que eres una persona y no un bot. Tarda un momento y despu&eacute;s sigues directo a la p&aacute;gina que quer&iacute;as.',
    rateTitle: '&iexcl;Vaya, qu&eacute; rapidez!',
    rateBody: 'Han llegado muchas peticiones desde tu conexi&oacute;n en poco tiempo, as&iacute; que hemos hecho una pausa. Int&eacute;ntalo de nuevo en un minuto.',
    blockedTitle: 'Hemos detenido esta petici&oacute;n',
    blockedBody: 'Nuestra protecci&oacute;n antibots la ha bloqueado. Si eres una persona y ves esto por error, lo sentimos: escr&iacute;benos y lo arreglamos enseguida.',
    helpLead: '&iquest;Algo no va bien? Escribe a',
    helpTail: 'y lo solucionamos.',
    details: 'Detalles t&eacute;cnicos',
    labelReason: 'Motivo',
    labelIp: 'Tu direcci&oacute;n IP',
  },
  fr: {
    lang: 'fr',
    loginTitle: 'Connecte-toi pour continuer',
    loginBody: 'Des robots d&rsquo;extraction automatique arrivent depuis ce r&eacute;seau, donc ici nous montrons les r&eacute;sultats et statistiques uniquement aux puzzleurs connect&eacute;s. Connecte-toi (ou cr&eacute;e un compte gratuit) et tu continues directement vers cette page. Tu viens de t&rsquo;inscrire&nbsp;? Confirme d&rsquo;abord ton e-mail.',
    challengeLoginHint: 'Tu as un compte&nbsp;? Les puzzleurs connect&eacute;s sont reconnus automatiquement et ne voient jamais cette v&eacute;rification.',
    challengeLoginCta: 'Se connecter',
    challengeTitle: 'D&eacute;sol&eacute; de te d&eacute;ranger&nbsp;!',
    challengeBody: 'On v&eacute;rifie simplement que tu es un vrai puzzleur et pas un robot. C&rsquo;est l&rsquo;affaire d&rsquo;un instant &mdash; ensuite tu continues vers ta page.',
    rateTitle: 'Oh l&agrave;, quelle vitesse&nbsp;!',
    rateBody: 'Beaucoup de requ&ecirc;tes sont arriv&eacute;es depuis ta connexion en peu de temps, alors on fait une petite pause. R&eacute;essaie dans une minute.',
    blockedTitle: 'Nous avons arr&ecirc;t&eacute; cette requ&ecirc;te',
    blockedBody: 'Notre protection anti-robots l&rsquo;a bloqu&eacute;e. Si tu es un vrai puzzleur et que tu vois ceci par erreur, d&eacute;sol&eacute; &mdash; &eacute;cris-nous et on corrige tout de suite.',
    helpLead: 'Un souci&nbsp;? &Eacute;cris &agrave;',
    helpTail: 'et on s&rsquo;en occupe.',
    details: 'D&eacute;tails techniques',
    labelReason: 'Motif',
    labelIp: 'Ton adresse IP',
  },
  ja: {
    lang: 'ja',
    loginTitle: '続けるにはログインしてください',
    loginBody: 'このネットワークからは自動収集ボットのアクセスが続いているため、結果と統計はログイン中のパズラーにのみ表示しています。ログイン（または無料アカウントを作成）すると、このページにそのまま進めます。登録したばかりの方は、先にメールアドレスを確認してください。',
    challengeLoginHint: 'アカウントをお持ちですか？ログイン中のパズラーは自動的に認識され、この確認は表示されません。',
    challengeLoginCta: 'ログイン',
    challengeTitle: 'お手数をおかけします！',
    challengeBody: 'ボットではなく本物のパズラーであることを確認しています。すぐに終わり、そのまま目的のページに進めます。',
    rateTitle: 'アクセスが少し速すぎるようです',
    rateBody: '短時間に多くのリクエストが届いたため、少しの間お待ちいただいています。1分ほどしてからもう一度お試しください。',
    blockedTitle: 'このリクエストを停止しました',
    blockedBody: 'ボット対策によりブロックされました。本物のパズラーの方に誤って表示されている場合は申し訳ありません。ご連絡いただければすぐに対応します。',
    helpLead: 'うまくいかない場合は',
    helpTail: 'までご連絡ください。',
    details: '技術的な詳細',
    labelReason: '理由',
    labelIp: 'あなたのIPアドレス',
  },
};

function detectPageLocale(requestPath, acceptLanguage) {
  const fromPath = /^\/(en|cs|de|es|fr|ja)(\/|$)/i.exec(requestPath || '');
  if (fromPath) return fromPath[1].toLowerCase();
  const header = (acceptLanguage || '').toLowerCase();
  for (const code of ['cs', 'ja', 'de', 'es', 'fr']) {
    if (header.startsWith(code) || header.includes(`,${code}`) || header.includes(` ${code}`)) return code;
  }
  return 'en';
}

// Reasons are server-side constants, but they interpolate counters and locale
// names — escape anyway. A block page must never become an injection surface.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Renders one of the three visitor-facing pages.
 *   kind: 'challenge' | 'ratelimit' | 'blocked'
 * The challenge page keeps its exact solve mechanics (widget + __bbSolved
 * callback appending the token to the current URL) — only the wrapper changed.
 */
function renderPage(kind, { reason = '', locale = 'en', ip = '' } = {}) {
  const t = PAGE_STRINGS[locale] || PAGE_STRINGS.en;
  const title = kind === 'challenge' ? t.challengeTitle : kind === 'ratelimit' ? t.rateTitle
    : kind === 'login' ? t.loginTitle : t.blockedTitle;
  const body = kind === 'challenge' ? t.challengeBody : kind === 'ratelimit' ? t.rateBody
    : kind === 'login' ? t.loginBody : t.blockedBody;

  // Logged-in users carry the app-issued __bb_trust cookie and are never
  // challenged — say so, with a way in. The script below points the link back
  // at the page they wanted (/login?return=…; the app validates the target).
  const widget = kind === 'challenge' ? `
    <div class="widget">
      <div class="cf-turnstile" data-sitekey="${TURNSTILE_SITE_KEY}" data-callback="__bbSolved"></div>
    </div>
    <p class="login-hint">${t.challengeLoginHint} <a id="bb-login" href="/login">${t.challengeLoginCta}</a></p>`
    : kind === 'login' ? `
    <p class="login-hint"><a id="bb-login" href="/login">${t.challengeLoginCta}</a></p>` : '';

  // Reason AND client IP: everything a wrongly-blocked visitor needs to paste
  // into a support mail, so Jan can allowlist the exact address (D47 pattern).
  const detailRows = [
    reason ? `<div><span>${t.labelReason}:</span> ${escapeHtml(reason)}</div>` : '',
    ip ? `<div><span>${t.labelIp}:</span> ${escapeHtml(ip)}</div>` : '',
  ].join('');
  const details = detailRows ? `
    <details>
      <summary>${t.details}</summary>
      <div class="reason">${detailRows}</div>
    </details>` : '';

  const returnScript = `
  <script>
    (function () {
      try {
        var url = new URL(window.location.href);
        url.searchParams.delete('${CHALLENGE_TOKEN_PARAM}');
        var back = url.pathname + url.search;
        if (back.indexOf('/login') === -1) {
          document.getElementById('bb-login').href = '/login?return=' + encodeURIComponent(back);
        }
      } catch (e) { /* plain /login link stays */ }
    })();
  </script>`;
  const scripts = kind === 'login' ? returnScript : kind === 'challenge' ? `${returnScript}
  <script>
    function __bbSolved(token) {
      try {
        var url = new URL(window.location.href);
        url.searchParams.set('${CHALLENGE_TOKEN_PARAM}', token);
        window.location.replace(url.toString());
      } catch (e) {
        var sep = window.location.search ? '&' : '?';
        window.location.href = window.location.href + sep + '${CHALLENGE_TOKEN_PARAM}=' + encodeURIComponent(token);
      }
    }
  </script>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : '';

  return `<!DOCTYPE html>
<html lang="${t.lang}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <meta name="theme-color" content="#fe696a">
  <title>${title} &mdash; MySpeedPuzzling</title>
  <style>${BRAND_CSS}</style>
</head>
<body>
  <main class="card">
    <img class="logo" src="/img/speedpuzzling-logo.svg" alt="MySpeedPuzzling" onerror="this.style.display='none'">
    <h1>${title}</h1>
    <p>${body}</p>${widget}
    <div class="foot">
      ${t.helpLead} <a href="mailto:${CONTACT_EMAIL}?subject=MySpeedPuzzling%20access">${CONTACT_EMAIL}</a> ${t.helpTail}
      ${details}
    </div>
  </main>${scripts}
</body>
</html>`;
}


// =============================================================================
// HTTP SERVER
// =============================================================================

// FAIL OPEN on internal errors. The handler is async (challenge verification
// awaits siteverify); an uncaught throw would be an unhandled rejection and
// CRASH the process — and a dead forwardAuth service makes Traefik answer 500
// on every page of the site until Docker restarts us. A bug in the blocker
// must degrade to "not blocking", never to "blocking everyone" — same
// philosophy as the CrowdSec bouncer's fail-open on LAPI loss.
const server = http.createServer((req, res) => {
  if (req.url === HEALTH_PATH && !req.headers['x-forwarded-uri']) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  handleRequest(req, res).catch((err) => {
    console.error(`[ERROR] handler failed open: ${err.stack || err.message}`);
    if (!res.headersSent) {
      res.writeHead(200);
    }
    res.end('OK');
  });
});

// D108 (2026-11-18): login wall for the Turnstile-solving fleet. An anonymous
// (no valid __bb_trust) Linux desktop browser on a hosting / proxy exit gets
// the "please log in" page instead of a challenge it would pay to solve. Over
// 24 h (2026-11-17/18) 1,218 of the 1,221 hosting-exit solvers were "X11;
// Linux" Chrome on one-solve-per-IP proxies, and none of 1,638 logged-in
// samples was a Linux desktop on a hosting network. Verified crawlers and
// Google's ranges returned earlier; auth / legal pages, the homepages and
// everything non-HTML stay open. Kill switch: LOGIN_WALL=0.
const LOGIN_WALL_ENABLED = process.env.LOGIN_WALL !== '0';
const LINUX_DESKTOP_UA = /X11; (?:Linux|Ubuntu|Fedora)/;

function isLoginWallRequest(ip, userAgent, headers, requestPath) {
  if (!LOGIN_WALL_ENABLED) return null;
  if (!LINUX_DESKTOP_UA.test(userAgent) || /Android|CrOS/.test(userAgent)) return null;
  if (!isScorableRequest(headers, requestPath) || isScoringExemptPath(requestPath)) return null;
  const bare = requestPath.split('?')[0].split('#')[0];
  if (/^\/(?:(?:en|cs|de|es|fr|ja)\/?)?$/.test(bare)) return null;  // homepages
  return hostingClass(ip);
}

function serveLoginWall(res, locale, ip, hosting) {
  res.writeHead(403, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Blocked-Reason': 'login_wall',
  });
  res.end(renderPage('login', { reason: `Login required on this network (${hosting})`, locale, ip }));
}

async function handleRequest(req, res) {
  // Only the real User-Agent. `X-Forwarded-User-Agent` was read first until
  // 2026-11-16 — nothing on the path sets it, so it was a client-chosen value
  // (Traefik and the gate pass it through): "Chrome" to the app, "Stripe/1.0"
  // to us. Truncated before any regex, Map key or log line (D98: an 8 KB UA
  // made the blocked-bots scan ~4.6 ms and the rate-limit Map ~15 KB/entry).
  const userAgent = (req.headers['user-agent'] || '').slice(0, MAX_UA_LENGTH);
  const requestMethod = (req.headers['x-forwarded-method'] || 'GET').toUpperCase();
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const requestPath = req.headers['x-forwarded-uri'] || req.url || '/';
  const originalProtocol = req.headers['x-original-protocol'] || '';
  // Language for any page served below (URL prefix first, then Accept-Language).
  // Computed once: a wrongly-blocked Czech puzzler reads a Czech apology.
  const locale = detectPageLocale(requestPath, req.headers['accept-language']);

  // Skip rate limiting for static assets
  if (isStaticAsset(requestPath)) {
    res.writeHead(200);
    res.end('OK');
    return;
  }

  // Whitelist search engine bots and social media crawlers. Verified (rDNS)
  // crawlers pass unlimited; UA-only entries pass under a per-IP cap; refuted
  // impersonators ("Googlebot" from a Hetzner VM) fall through to the normal
  // pipeline below — no privileges, no instant block.
  const whitelisted = await checkWhitelistedBot(userAgent, ip, requestMethod, requestPath);
  if (whitelisted && whitelisted.allow) {
    allowRequest(res, 'crawler', ip, userAgent, requestPath, req.headers);
    return;
  }

  // Google's published crawler/fetcher ranges — verified by IP, whatever the
  // UA says (OAuth brand verification sends just "Google"). Capped per IP.
  if (isGooglePublishedIp(ip)) {
    if (isCrawlerCapped('Google (published range)', ip)) {
      logBlocked('crawler_capped', ip, userAgent,
        `Google (published range) over ${WHITELIST_BOT_CAP}/min per-IP crawler cap`, requestPath);
      res.writeHead(429, {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After': '60',
        'X-Blocked-Reason': 'crawler_cap',
      });
      res.end(renderPage('ratelimit', { locale, ip }));
      return;
    }
    if (isGoogleUserControlledOnly(ip)) {
      logWould('would_score', 'google_user_triggered', ip, userAgent, requestPath);
    }
    allowRequest(res, 'google', ip, userAgent, requestPath, req.headers);
    return;
  }

  if (whitelisted) {
    if (whitelisted.capped) {
      logBlocked('crawler_capped', ip, userAgent,
        `${whitelisted.name} over ${WHITELIST_BOT_CAP}/min per-IP crawler cap`, requestPath);
      res.writeHead(429, {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After': '60',
        'X-Blocked-Reason': 'crawler_cap',
      });
      res.end(renderPage('ratelimit', { locale, ip }));
      return;
    }
    // whitelisted.fake — log once per request and continue the pipeline
    logBlocked('fake_crawler', ip, userAgent,
      `UA claims ${whitelisted.name} but rDNS does not confirm it`, requestPath);
  }

  // Challenge solve callback (?__bb_token=...). MUST run before the blocking
  // rules — the request carrying the token comes from a still-blocked client.
  if (CHALLENGE_ENABLED) {
    const tokenReq = extractChallengeToken(requestPath);
    if (tokenReq) {
      if (isVerifyRateLimited(ip)) {
        logChallenge('challenge_verify_limited', ip, userAgent, 'Too many verify attempts', requestPath);
        res.writeHead(429, { 'Retry-After': '60' });
        res.end();
        return;
      }
      const solved = await verifyTurnstileToken(tokenReq.token, ip);
      if (solved) {
        // A permabanned human just proved themselves — lift the ban. The
        // behavioral trackers keep running, so a scraper that solves once and
        // keeps hammering earns a fresh ban (and another solve, per exit IP).
        if (bannedIPs.has(ip)) {
          bannedIPs.delete(ip);
          saveBannedIPs();
          console.log(`[CHALLENGE] Lifted permaban for ${ip} after solved challenge`);
        }
        logChallenge('challenge_passed', ip, userAgent, 'Challenge solved', tokenReq.cleanUri);
        res.writeHead(302, {
          'Set-Cookie': makePassCookie(ip),
          'Location': buildRedirectUrl(req.headers, tokenReq.cleanUri),
          'Cache-Control': 'no-store',
        });
        res.end();
        return;
      }
      logChallenge('challenge_failed', ip, userAgent, 'Token rejected by siteverify', tokenReq.cleanUri);
      // Redirect to the clean URL: the still-blocked client meets the
      // challenge page again there and can retry.
      res.writeHead(302, {
        'Location': buildRedirectUrl(req.headers, tokenReq.cleanUri),
        'Cache-Control': 'no-store',
      });
      res.end();
      return;
    }
  }

  // Trusted human: the app vouched for this browser (logged-in account, see
  // the __bb_trust config comment). Full bypass — including permabans and
  // rate limits: competition venues put 1000+ real users behind one WiFi IP,
  // and a ban earned by one device must never lock out the logged-in rest.
  // The uid is opaque (no PII); a single uid fanning out across many IPs in
  // the daily logs would expose a registered scraper account.
  const trustedUid = getTrustedUid(req.headers['cookie']);
  if (trustedUid) {
    recordTrustFanout(trustedUid, ip, userAgent, requestPath);
    // D108: a blocked account is refused outright; a revoked one (fan-out)
    // falls through and is handled like any anonymous visitor.
    if (blockedUids.has(trustedUid)) {
      logBlocked('uid_blocked', ip, userAgent, `Account ${trustedUid} is on the block list`, requestPath,
        { uid: trustedUid });
      res.writeHead(403, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Blocked-Reason': 'uid_blocked',
      });
      res.end(renderPage('blocked', { reason: 'Account blocked', locale, ip }));
      return;
    }
    if (!isTrustRevoked(trustedUid)) {
      allowRequest(res, 'trust', ip, userAgent, requestPath, req.headers, { uid: trustedUid });
      return;
    }
  }

  // A valid pass cookie bypasses ONLY the challenge-eligible heuristics below
  // (UA signatures, the 43/8 combo). Hard rules, rate limits and scrape
  // detection still apply to cookie holders. Permabans need no bypass —
  // solving the challenge lifted them.
  // Hosting-class passes are short-lived (HOSTING_PASS_TTL_MS) and every pass
  // carries a page budget, consumed in the ladder below (D96).
  const pass = CHALLENGE_ENABLED ? readPassCookie(req.headers['cookie'], ip) : null;
  const hasPass = pass !== null;

  // Check permanent ban
  if (isPermanentlyBanned(ip)) {
    const info = bannedIPs.get(ip);
    logBlocked('permaban', ip, userAgent, info.reason, requestPath);
    serveChallengeOrBlock(res, `Permanently banned: ${info.reason}`, 'permaban', locale, ip);
    return;
  }

  // Check blocked paths
  for (const { pattern, reason } of BLOCKED_PATHS) {
    if (pattern.test(requestPath)) {
      logBlocked('path', ip, userAgent, reason, requestPath);

      const html = renderPage('blocked', { reason, locale, ip });

      res.writeHead(403, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Blocked-Reason': reason,
      });
      res.end(html);
      return;
    }
  }

  // Check blocked bots
  for (const { pattern, reason, challenge } of BLOCKED_BOTS) {
    if (pattern.test(userAgent)) {
      // Solved challenge exempts the UA-signature rules — a verified human
      // with a UA-freezing privacy tool browses normally from here on.
      if (challenge && hasPass) {
        continue;
      }
      logBlocked('bot', ip, userAgent, reason, requestPath);

      if (challenge) {
        serveChallengeOrBlock(res, reason, reason, locale, ip);
        return;
      }

      const html = renderPage('blocked', { reason, locale, ip });

      res.writeHead(403, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Blocked-Reason': reason,
      });
      res.end(html);
      return;
    }
  }

  // Block empty user agent on HTTP/1.1 (scanners/scrapers — real browsers always send UA)
  if ((!userAgent || userAgent.trim().length === 0) && originalProtocol === 'HTTP/1.1') {
    const reason = 'Empty user agent on HTTP/1.1 (scanner/scraper)';
    logBlocked('bot', ip, userAgent || '', reason, requestPath);
    const html = renderPage('blocked', { reason, locale, ip });
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'empty_ua',
    });
    res.end(html);
    return;
  }

  // Check blocked subnets (known botnet IPs)
  const subnetBlock = isBlockedSubnet(ip);
  if (subnetBlock) {
    logBlocked('subnet', ip, userAgent, subnetBlock, requestPath);
    const html = renderPage('blocked', { reason: subnetBlock, locale, ip });
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'blocked_subnet',
    });
    res.end(html);
    return;
  }

  // Check Chinese botnet (combination detection).
  // Challenge-eligible: the rule spans the ENTIRE 43.0.0.0/8 — which contains
  // real Asian residential ISPs — combined with the most common OS+browser on
  // earth. The riskiest heuristic we run (5.1k distinct IPs / 8 days); any
  // real human inside gets a way through, the botnet doesn't solve widgets.
  if (!hasPass && isChineseBotnet(ip, userAgent)) {
    // Reason string updated 2026-08 (was "...HTTP/1.1 + outdated Chrome"):
    // the rule matches ANY Chrome version and never saw protocol — the old
    // wording misdescribed what fired 35k+ times during the July wave.
    const reason = 'Chinese cloud botnet (43.x + Windows 10 + Chrome)';
    logBlocked('botnet', ip, userAgent, reason, requestPath);
    serveChallengeOrBlock(res, reason, 'chinese_botnet', locale, ip);
    return;
  }

  // Check fake iOS bot from Chinese cloud
  if (isFakeIOSBot(ip, userAgent)) {
    const reason = 'Fake iOS bot from Chinese cloud';
    logBlocked('botnet', ip, userAgent, reason, requestPath);
    const html = renderPage('blocked', { reason, locale, ip });
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'fake_ios_bot',
    });
    res.end(html);
    return;
  }

  // Check cloud botnet (HTTP/1.1 + Windows Chrome + cloud provider IP)
  const cloudProvider = isCloudBotnet(ip, userAgent, originalProtocol);
  if (cloudProvider) {
    const reason = `Cloud botnet (${cloudProvider} + HTTP/1.1 + Chrome)`;
    logBlocked('cloud_botnet', ip, userAgent, reason, requestPath);
    const html = renderPage('blocked', { reason, locale, ip });
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'cloud_botnet',
    });
    res.end(html);
    return;
  }

  // Check HTTP/1.1 + browser UA (residential proxy botnet)
  // Real browsers always negotiate HTTP/2+ via TLS ALPN.
  // HTTP/1.1 + Chrome/Firefox = bot library (requests, httpx, curl, etc.)
  if (isHTTP1Browser(userAgent, originalProtocol)) {
    const reason = 'HTTP/1.1 with browser UA (real browsers use HTTP/2+)';
    logBlocked('http1_browser', ip, userAgent, reason, requestPath);
    const html = renderPage('blocked', { reason, locale, ip });
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'http1_browser',
    });
    res.end(html);
    return;
  }

  // Check locale switching (may trigger permanent ban).
  // The ban page is challenge-eligible — permabans have the highest cost when
  // wrong (30 days), and solving the challenge lifts the ban. The detection
  // itself still runs for cookie holders: prove-human ≠ scrape-freely, and a
  // re-triggered ban costs another solve.
  if (checkLocaleSwitch(ip, requestPath)) {
    const info = bannedIPs.get(ip);
    logBlocked('locale_switch', ip, userAgent, info.reason, requestPath);
    serveChallengeOrBlock(res, info.reason, 'locale_switch');
    return;
  }

  // Check page scraping (puzzle/profile) — progressive: 429 on 1st/2nd strike, permaban on 3rd
  const scrapeResult = checkPageScraping(ip, userAgent, requestPath);
  if (scrapeResult) {
    if (scrapeResult.banned) {
      logBlocked('page_scrape_ban', ip, userAgent, scrapeResult.reason, requestPath);
      serveChallengeOrBlock(res, `Permanently banned: ${scrapeResult.reason}`, 'page_scrape_ban', locale, ip);
      return;
    } else {
      logBlocked('page_scrape', ip, userAgent,
        `Strike ${scrapeResult.strikes}/${SCRAPE_STRIKES_FOR_BAN}: ${scrapeResult.reason}`, requestPath);

      res.writeHead(429, {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After': '300',
        'X-Blocked-Reason': 'page_scrape',
      });
      res.end(renderPage('ratelimit', { locale, ip }));
      return;
    }
  }

  // Check rate limit
  if (isRateLimited(ip, userAgent)) {
    logBlocked('rate_limit', ip, userAgent, 'Too many requests', requestPath);

    res.writeHead(429, {
      'Content-Type': 'text/html; charset=utf-8',
      'Retry-After': '60',
      'X-Blocked-Reason': 'rate_limit',
    });
    res.end(renderPage('ratelimit', { locale, ip }));
    return;
  }

  // D108 login wall: before the ladder and regardless of a pass - a solved
  // challenge is exactly what this fleet buys.
  const wallHosting = isLoginWallRequest(ip, userAgent, req.headers, requestPath);
  if (wallHosting) {
    logBlocked('login_wall', ip, userAgent, `Anonymous Linux desktop on ${wallHosting}`, requestPath,
      { hosting: wallHosting, has_pass: hasPass, revoked_uid: trustedUid || undefined });
    serveLoginWall(res, locale, ip, wallHosting);
    return;
  }

  // Risk-scoring ladder (D50) — the LAST gate, after every deterministic rule
  // passed. Scores the anonymous HTML surface; above the threshold it serves
  // the Turnstile challenge (managed mode: invisible to genuine browsers).
  // A pass holder skips the ladder only while the pass's budget lasts (D96):
  // past it the request is scored again — a hosting exit with `pass_exhausted`
  // added (dc_asn 40 + 25 = a new challenge at any pressure), a residential
  // reader with no extra component (their cookie-carrying, coherent headers
  // normally score ~0).
  // In 'log' (shadow) mode nothing is ever acted on.
  const scorable = SCORING_MODE !== 'off' && isScorableRequest(req.headers, requestPath)
    && !isScoringExemptPath(requestPath);
  let passExhausted = false;
  if (scorable && hasPass) {
    passExhausted = !consumePassPage(pass, ip, userAgent, requestPath);
  }
  let risk = null;
  if (scorable && (!hasPass || passExhausted)) {
    // Pass holders never fed the pressure window before D96; over-budget ones
    // must not start inflating it for everyone else — they read it only.
    const rate5m = hasPass ? surgePeek() : surgeTick();
    risk = computeRiskScore(ip, userAgent, requestPath, req.headers, rate5m,
      { passExhausted: passExhausted && hostingClass(ip) !== null });
    if (risk.score >= SCORE_THRESHOLD) {
      const detail = `Risk score ${risk.score} (base ${risk.base} × pressure ${risk.pressure})`;
      // Challenge only when the challenge stack is live — a heuristic score
      // must NEVER produce a hard 403, so without Turnstile keys we shadow-log.
      if (SCORING_MODE === 'challenge' && CHALLENGE_ENABLED) {
        logBlocked('risk_challenge', ip, userAgent, detail, requestPath, risk);
        serveChallengeOrBlock(res, 'Automated traffic suspected', 'risk_score', locale, ip);
        return;
      }
      logBlocked('risk_shadow', ip, userAgent, detail, requestPath, risk);
    } else if (risk.score >= SCORE_LOG_MIN) {
      // Sub-threshold observability: the shadow phase tunes the threshold
      // from this distribution instead of guessing.
      logBlocked('risk_observe', ip, userAgent, `Risk score ${risk.score}`, requestPath, risk);
    }
  }

  // D98 telemetry: what the non-HTML-Accept skip lets through.
  if (!scorable && SCORING_MODE !== 'off' && isAcceptBypass(req.headers, requestPath)
    && !isScoringExemptPath(requestPath)) {
    const shadow = computeRiskScore(ip, userAgent, requestPath, req.headers, surgePeek());
    if (shadow.score >= SCORE_THRESHOLD) {
      logWould('would_score', 'non_html_accept', ip, userAgent, requestPath, {
        score: shadow.score, components: shadow.components, has_pass: hasPass,
        accept: (req.headers['accept'] || '').slice(0, 80),
        sec_fetch_dest: req.headers['sec-fetch-dest'] || null,
        sec_fetch_mode: req.headers['sec-fetch-mode'] || null,
      });
    }
  }

  // Allow request
  allowRequest(res, hasPass ? (passExhausted ? 'pass_exhausted' : 'pass') : 'clean',
    ip, userAgent, requestPath, req.headers, { scorable, risk });
}

/**
 * Answers 200 (allow). For hosting-class exits without a trust cookie it adds
 * `X-BB-Analytics: off` (the app then skips Google Analytics); verified
 * crawlers and trusted humans never get it. A random ALLOW_SAMPLE_RATE share
 * of allows is logged as `allow_sample` — the only window onto allowed traffic.
 */
function allowRequest(res, via, ip, userAgent, requestPath, headers, info = {}) {
  const hosting = (via === 'trust' || via === 'crawler' || via === 'google') ? null : hostingClass(ip);
  if (hosting) {
    res.writeHead(200, { [ANALYTICS_HEADER]: 'off' });
  } else {
    res.writeHead(200);
  }
  res.end('OK');

  if (ALLOW_SAMPLE_RATE > 0 && Math.random() < ALLOW_SAMPLE_RATE) {
    try {
      sampleAllow(via, ip, userAgent, requestPath, headers, hosting, info);
    } catch (err) {
      console.error(`[ALLOW_SAMPLE] ${err.message}`);
    }
  }
}

function sampleAllow(via, ip, userAgent, requestPath, headers, hosting, info) {
  const scorable = info.scorable !== undefined
    ? info.scorable
    : (isScorableRequest(headers, requestPath) && !isScoringExemptPath(requestPath));
  // Score what the ladder WOULD say, even for pass/trust holders (no surge tick).
  const risk = info.risk || (scorable ? computeRiskScore(ip, userAgent, requestPath, headers, surgePeek()) : null);
  let refererHost = null;
  try { refererHost = headers['referer'] ? new URL(headers['referer']).host : null; } catch { refererHost = 'invalid'; }
  // Path WITHOUT the query string: logged-in users' URLs can carry reset /
  // OAuth tokens, and the sample never needs them.
  logBlocked('allow_sample', ip, userAgent || '', `Allowed via ${via}`, String(requestPath).split('?')[0], {
    via,
    hosting: hosting || hostingClass(ip) || null,
    analytics_off: Boolean(hosting),
    country: geoCountry(ip),
    scorable,
    score: risk ? risk.score : null,
    components: risk ? risk.components : null,
    method: (headers['x-forwarded-method'] || 'GET').toUpperCase(),
    accept: (headers['accept'] || '').slice(0, 80),
    accept_language: (headers['accept-language'] || '').slice(0, 40),
    sec_fetch_site: headers['sec-fetch-site'] || null,
    sec_fetch_dest: headers['sec-fetch-dest'] || null,
    sec_ch_ua: Boolean(headers['sec-ch-ua']),
    has_cookie: Boolean(headers['cookie']),
    referer_host: refererHost,
    uid: info.uid || null,
  });
}

// =============================================================================
// STARTUP
// =============================================================================

// Guarded so tests can `require('./server.js')` and exercise the helpers
// without starting the server or touching the log directory.
if (require.main === module) {

ensureLogDir();
loadBannedIPs();
loadRevokedUids();
reloadBlockedUids();
initGeoDb(GEODB_DIR);
loadGoogleRanges(GEODB_DIR);
if (GOOGLE_RANGES_REFRESH_HOURS > 0) {
  refreshGoogleRanges().catch(() => {});
  setInterval(() => { refreshGoogleRanges().catch(() => {}); },
    GOOGLE_RANGES_REFRESH_HOURS * 3600 * 1000).unref();
}

server.listen(PORT, () => {
  console.log(`Bot blocker middleware running on port ${PORT}`);
  console.log(`Rate limit: ${RATE_LIMIT} requests per ${RATE_WINDOW / 1000}s`);
  console.log(`Challenge: ${CHALLENGE_ENABLED ? `ENABLED (pass TTL ${CHALLENGE_COOKIE_TTL_MS / 3600000}h / ${PASS_PAGE_BUDGET} pages; hosting exits ${HOSTING_PASS_TTL_MS / 60000}min / ${HOSTING_PASS_PAGE_BUDGET} pages)` : 'disabled (missing TURNSTILE_SITE_KEY/TURNSTILE_SECRET_KEY/CHALLENGE_COOKIE_SECRET or CHALLENGE_ENABLED=false)'}`);
  console.log(`Allow sampling: ${ALLOW_SAMPLE_RATE * 100}% of allowed requests logged as allow_sample`);
  console.log(`Trust cookie: ${TRUST_ENABLED ? `ENABLED (TTL ${TRUST_COOKIE_TTL_MS / 86400000}d)` : 'disabled (no TRUST_COOKIE_SECRET/CHALLENGE_COOKIE_SECRET)'}`);
  console.log(`Risk scoring: ${SCORING_MODE} (threshold ${SCORE_THRESHOLD}, baseline ${SURGE_BASELINE_5M}/5min, high-risk: ${[...HIGH_RISK_COUNTRIES].join(',') || 'none'})`);
  console.log(`Locale detection: ${LOCALE_THRESHOLD} locales with ${LOCALE_MIN_HITS}+ hits each in ${LOCALE_WINDOW / 1000}s triggers ${BAN_DURATION / (24 * 60 * 60 * 1000)}-day ban`);
  console.log(`Page scrape detection: ${PUZZLE_SCRAPE_THRESHOLD} puzzles/${PUZZLE_SCRAPE_WINDOW / 1000}s, ${PROFILE_SCRAPE_THRESHOLD} profiles/${PROFILE_SCRAPE_WINDOW / 1000}s, ${SCRAPE_STRIKES_FOR_BAN} strikes to ban`);
  console.log(`Cloud botnet CIDR ranges: ${CLOUD_PROVIDER_CIDRS.length} (requires X-Original-Protocol header)`);
  console.log(`Banned IPs loaded: ${bannedIPs.size}`);
  console.log(`Whitelisted bot patterns: ${WHITELISTED_BOTS.length}`);
  console.log(`Blocked bot patterns: ${BLOCKED_BOTS.length}`);
  console.log(`Blocked CIDR subnets: ${BLOCKED_CIDRS.length}`);
  console.log(`Static asset patterns: ${STATIC_ASSET_PATTERNS.length}`);
  console.log(`Log directory: ${LOG_DIR} (block logs kept ${LOG_RETENTION_DAYS || 'forever'}${LOG_RETENTION_DAYS ? ' days' : ''})`);
  console.log(`Contact email: ${CONTACT_EMAIL}`);
  scheduleNextSummary();
  pruneOldBlockLogs().catch(err => console.error(`[RETENTION] ${err.message}`));
});

} // require.main guard

// Exported for unit tests only — the module never gets required in production.
module.exports = {
  server,
  // D98 hardening + telemetry
  staleChromeCutoff,
  staleFirefoxCutoff,
  isSafariFamilyUa,
  isAcceptBypass,
  isGoogleUserControlledOnly,
  capMap,
  slash24,
  recordTrustFanout,
  isTrustRevoked,
  reloadBlockedUids,
  isLoginWallRequest,
  TRUST_FANOUT_REVOKE,
  APPLE_LINK_PREVIEW_UA,
  MAX_UA_LENGTH,
  MAX_MAP_ENTRIES,
  signPassCookie,
  buildRedirectUrl,
  makePassCookie,
  hasValidPassCookie,
  readPassCookie,
  consumePassPage,
  hostingClass,
  isAppleRelay,
  passTtlFor,
  allowRequest,
  ANALYTICS_HEADER,
  ALLOW_SAMPLE_RATE,
  CHALLENGE_COOKIE_TTL_MS,
  HOSTING_PASS_TTL_MS,
  PASS_PAGE_BUDGET,
  HOSTING_PASS_PAGE_BUDGET,
  extractChallengeToken,
  verifyTurnstileToken,
  isVerifyRateLimited,
  BLOCKED_BOTS,
  CHALLENGE_ENABLED,
  CHALLENGE_COOKIE_NAME,
  CHALLENGE_TOKEN_PARAM,
  // Trust cookie
  getTrustedUid,
  TRUST_COOKIE_NAME,
  // Risk scoring
  computeRiskScore,
  isScorableRequest,
  uaOsFamily,
  SCORE_WEIGHTS,
  SCORE_THRESHOLD,
  // GeoDB
  initGeoDb,
  geoCountry,
  asnDatacenterOrg,
  crawlerAsn,
  crawlerAsnDataLoaded,
  // Daily summary
  generateDailySummary,
  summaryReasonKey,
  pruneOldBlockLogs,
  LOG_RETENTION_DAYS,
  HEALTH_PATH,
  // Visitor-facing pages
  renderPage,
  detectPageLocale,
  PAGE_STRINGS,
  // Crawler verification
  checkWhitelistedBot,
  verifyCrawlerRdns,
  _setDnsForTests,
  isCrawlerCapped,
  WHITELIST_BOT_CAP,
  // Google published fetcher ranges + ladder-exempt paths
  parseGoogleRangeDocument,
  setGoogleRanges,
  loadGoogleRanges,
  refreshGoogleRanges,
  isGooglePublishedIp,
  isScoringExemptPath,
};
