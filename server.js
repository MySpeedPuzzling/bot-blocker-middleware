const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns');

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONTACT_EMAIL = process.env.CONTACT_EMAIL || 'j.mikes@me.com';
const LOG_DIR = process.env.LOG_DIR || '/var/log/bot-blocker';
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
const CHALLENGE_COOKIE_TTL_MS = (parseInt(process.env.CHALLENGE_COOKIE_TTL_DAYS, 10) || 7) * 24 * 60 * 60 * 1000;
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
// bots, meta-webindexer): UA strings are trivially spoofable, so the uncapped
// whitelist is reserved for rDNS-verified crawlers.
const WHITELIST_BOT_CAP = parseInt(process.env.WHITELIST_BOT_CAP, 10) || 30;

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
//   capped: true — UA-only whitelist with a WHITELIST_BOT_CAP/min per-IP
//                  budget (429 above it). For preview bots that fetch a page
//                  per human share, the cap is unreachable; for a scraper
//                  hiding behind "WhatsApp" it's a ceiling. meta-webindexer
//                  sits here on purpose: verified via .fbsv.net but capped —
//                  8k+ pages in 3 days is not link-preview behavior.
//   (neither)    — legacy unlimited UA-only pass. Reserved for Stripe
//                  webhooks: capping those risks dropped payment events, a
//                  far worse failure than tolerating a spoofable UA that was
//                  spoofable yesterday too.
const RDNS_GOOGLE = ['.googlebot.com', '.google.com'];
const RDNS_BING = ['.search.msn.com'];
const RDNS_META = ['.fbsv.net'];

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
  { pattern: /facebookexternalhit/i, name: 'Facebook', rdns: RDNS_META, capped: true },
  { pattern: /meta-externalagent/i, name: 'Meta (external agent)', rdns: RDNS_META, capped: true },
  { pattern: /meta-webindexer/i, name: 'Meta (web indexer)', rdns: RDNS_META, capped: true },
  { pattern: /Twitterbot/i, name: 'Twitter/X', capped: true },
  { pattern: /LinkedInBot/i, name: 'LinkedIn', capped: true },
  { pattern: /WhatsApp/i, name: 'WhatsApp', capped: true },
  { pattern: /Slackbot/i, name: 'Slack', capped: true },
  { pattern: /TelegramBot/i, name: 'Telegram', capped: true },
  { pattern: /Discordbot/i, name: 'Discord', capped: true },

  // Monitoring
  { pattern: /SentryUptimeBot/i, name: 'Sentry Uptime', capped: true },
  { pattern: /Stripe\//i, name: 'Stripe' },  // uncapped: never risk webhook delivery
];

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

function _setDnsForTests(reverseFn, resolveFn) {
  dnsReverse = reverseFn;
  dnsResolve = resolveFn;
  rdnsCache.clear();
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
  } catch (err) {
    // NXDOMAIN/no-PTR is a definitive answer — a real crawler always has one.
    // Anything else (timeout, SERVFAIL) is OUR uncertainty: fail open, no cache.
    if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) {
      state = 'fake';
    } else {
      return 'error';
    }
  }

  rdnsCache.set(ip, { state, exp: Date.now() + (state === 'ok' ? RDNS_OK_TTL_MS : RDNS_FAKE_TTL_MS) });
  return state;
}

const crawlerBuckets = new Map();  // "name|ip" -> { count, windowStart }

function isCrawlerCapped(name, ip) {
  const key = name + '|' + ip;
  const now = Date.now();
  const record = crawlerBuckets.get(key);
  if (!record || now - record.windowStart > 60000) {
    crawlerBuckets.set(key, { count: 1, windowStart: now });
    return false;
  }
  record.count++;
  return record.count > WHITELIST_BOT_CAP;
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
async function checkWhitelistedBot(userAgent, ip) {
  if (!userAgent) return null;
  for (const entry of WHITELISTED_BOTS) {
    if (!entry.pattern.test(userAgent)) continue;
    if (entry.rdns) {
      const state = await verifyCrawlerRdns(ip, entry.rdns);
      if (state === 'fake') return { name: entry.name, fake: true };
      // 'ok' → verified; 'error' → fail open (uncached, retried next request)
    }
    if (entry.capped && isCrawlerCapped(entry.name, ip)) {
      return { name: entry.name, capped: true };
    }
    return { name: entry.name, allow: true };
  }
  return null;
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

const geoDb = { countryBuf: null, asnBuf: null, countries: [], dcOrgs: [] };

function initGeoDb(dir) {
  geoDb.countryBuf = null;
  geoDb.asnBuf = null;
  geoDb.countries = [];
  geoDb.dcOrgs = [];
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
    geoDb.countries = meta.countries || [];
    geoDb.dcOrgs = meta.dcOrgs || [];
    geoDb.countryBuf = fs.readFileSync(path.join(dir, 'country.bin'));
    geoDb.asnBuf = fs.readFileSync(path.join(dir, 'asn.bin'));
    console.log(`[GEODB] Loaded ${geoDb.countryBuf.length / 9} country ranges, `
      + `${geoDb.asnBuf.length / 10} ASN ranges (built ${meta.built || 'unknown'})`);
    return true;
  } catch (err) {
    geoDb.countryBuf = null;
    geoDb.asnBuf = null;
    console.log(`[GEODB] Not available (${err.message}) — geo/ASN risk signals disabled`);
    return false;
  }
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
  cookieless_same_origin: 25,  // claims in-site navigation with an empty cookie jar
  cookieless_deep_direct: 10,  // cookieless, referer-less entry straight to deep content
};

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

function surgeTick() {
  const minute = Math.floor(Date.now() / 60000);
  if (minute !== surgeMinute) {
    const gap = Math.min(5, minute - surgeMinute);
    for (let i = 1; i <= gap; i++) {
      surgeBuckets[(surgeMinute + i) % 5] = 0;
    }
    surgeMinute = minute;
  }
  surgeBuckets[minute % 5]++;
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
  const accept = headers['accept'] || '';
  if (accept && !accept.includes('text/html') && !accept.includes('*/*')) return false;
  return true;
}

/**
 * Pure scoring function — rate5m is passed in (tests need determinism).
 * Returns { score, base, pressure, components }.
 */
function computeRiskScore(ip, userAgent, requestPath, headers, rate5m) {
  const ua = userAgent || '';
  const components = {};

  // --- IP reputation ---------------------------------------------------------
  const dcOrg = asnDatacenterOrg(ip);
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
  if (!hasCookies && headers['sec-fetch-site'] === 'same-origin') {
    components.cookieless_same_origin = SCORE_WEIGHTS.cookieless_same_origin;
  }
  if (!hasCookies && !headers['referer']
    && requestPath.split('?')[0].split('/').filter(Boolean).length >= 2) {
    components.cookieless_deep_direct = SCORE_WEIGHTS.cookieless_deep_direct;
  }

  // --- Pressure: auto-tighten under distributed crawl -----------------------
  const pressure = rate5m / SURGE_BASELINE_5M;
  if (pressure > 2 && locale && !hasCookies) {
    components.surge_locale_cookieless = SURGE_EXTRA_SCORE;
  }

  let base = 0;
  for (const value of Object.values(components)) base += value;
  const multiplier = Math.min(2.5, Math.max(1, pressure));
  const score = Math.round(base * multiplier);

  return { score, base, pressure: Math.round(pressure * 100) / 100, components };
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

function generateDailySummary() {
  const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
  const logFile = path.join(LOG_DIR, `blocked-${yesterday}.log`);

  if (!fs.existsSync(logFile)) {
    console.log(`[SUMMARY] No log file for ${yesterday}`);
    return;
  }

  try {
    const content = fs.readFileSync(logFile, 'utf8');
    const lines = content.trim().split('\n').filter(Boolean);

    const stats = { total: lines.length, byType: {}, byReason: {}, topIPs: {} };

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        stats.byType[entry.type] = (stats.byType[entry.type] || 0) + 1;
        stats.byReason[entry.reason] = (stats.byReason[entry.reason] || 0) + 1;
        stats.topIPs[entry.ip] = (stats.topIPs[entry.ip] || 0) + 1;
      } catch (e) {
        // Skip malformed lines
      }
    }

    const topIPs = Object.entries(stats.topIPs).sort((a, b) => b[1] - a[1]).slice(0, 10);

    const summary = `Daily Block Summary: ${yesterday}
================================

Total Blocked Requests: ${stats.total}

By Type:
${Object.entries(stats.byType).map(([k, v]) => `  ${k}: ${v}`).join('\n')}

By Reason:
${Object.entries(stats.byReason).map(([k, v]) => `  ${k}: ${v}`).join('\n')}

Top 10 Blocked IPs:
${topIPs.map(([ip, count]) => `  ${ip}: ${count}`).join('\n')}
`;

    fs.writeFileSync(path.join(LOG_DIR, `summary-${yesterday}.txt`), summary);
    console.log(`[SUMMARY] Generated for ${yesterday}: ${stats.total} blocks`);
  } catch (err) {
    console.error(`[SUMMARY] Failed: ${err.message}`);
  }
}

function scheduleNextSummary() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(0, 5, 0, 0);

  const msUntilSummary = tomorrow - now;

  setTimeout(() => {
    generateDailySummary();
    setInterval(generateDailySummary, 24 * 60 * 60 * 1000);
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

function saveBannedIPs() {
  try {
    const data = Object.fromEntries(bannedIPs);
    fs.writeFileSync(BANNED_IPS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('[BAN] Failed to save banned IPs:', err.message);
  }
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

function makePassCookie(ip) {
  const expiresMs = Date.now() + CHALLENGE_COOKIE_TTL_MS;
  const value = `${expiresMs}.${signPassCookie(ip, expiresMs)}`;
  const maxAgeSec = Math.floor(CHALLENGE_COOKIE_TTL_MS / 1000);
  return `${CHALLENGE_COOKIE_NAME}=${value}; Max-Age=${maxAgeSec}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

function hasValidPassCookie(cookieHeader, ip) {
  if (!cookieHeader) return false;

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
  if (!raw) return false;

  const dot = raw.indexOf('.');
  if (dot === -1) return false;

  const expiresMs = parseInt(raw.slice(0, dot), 10);
  if (!Number.isFinite(expiresMs) || Date.now() > expiresMs) return false;

  const expected = signPassCookie(ip, expiresMs);
  const actual = raw.slice(dot + 1);
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
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
function serveChallengeOrBlock(res, reason, headerReason) {
  if (!CHALLENGE_ENABLED) {
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': headerReason,
    });
    res.end(html);
    return;
  }
  const html = CHALLENGE_HTML.replace(/\{\{REASON\}\}/g, reason);
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

const RATE_LIMITED_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Blocked</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
      max-width: 480px;
      width: 100%;
      padding: 48px 40px;
      text-align: center;
    }
    .icon {
      font-size: 64px;
      margin-bottom: 24px;
    }
    h1 {
      color: #1a202c;
      font-size: 24px;
      font-weight: 700;
      margin-bottom: 16px;
    }
    p {
      color: #4a5568;
      font-size: 16px;
      line-height: 1.6;
      margin-bottom: 24px;
    }
    .contact {
      background: #f7fafc;
      border-radius: 12px;
      padding: 20px;
    }
    .contact a {
      color: #667eea;
      text-decoration: none;
      font-weight: 600;
    }
    .contact a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#128683;</div>
    <h1>Access Blocked</h1>
    <p>Due to suspicious activity (too many requests in short period of time), you have been blocked.</p>
    <div class="contact">
      <p style="margin-bottom: 0;">If this is a mistake or you would like to be un-blocked and start official collaboration, please reach out to us at <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></p>
    </div>
  </div>
</body>
</html>`;

const BOT_BLOCKED_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Blocked</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
      max-width: 520px;
      width: 100%;
      padding: 48px 40px;
      text-align: center;
    }
    .icon {
      font-size: 64px;
      margin-bottom: 24px;
    }
    h1 {
      color: #1a202c;
      font-size: 24px;
      font-weight: 700;
      margin-bottom: 16px;
    }
    p {
      color: #4a5568;
      font-size: 16px;
      line-height: 1.6;
      margin-bottom: 20px;
    }
    .reason {
      background: #fff5f5;
      border: 1px solid #feb2b2;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      font-family: monospace;
      font-size: 13px;
      color: #c53030;
      word-break: break-all;
      text-align: left;
    }
    .contact {
      background: #f7fafc;
      border-radius: 12px;
      padding: 20px;
    }
    .contact a {
      color: #f5576c;
      text-decoration: none;
      font-weight: 600;
    }
    .contact a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#129302;</div>
    <h1>Bot Detected</h1>
    <p>Your request has been blocked by our automated protection system.</p>
    <div class="reason">
      <strong>Reason:</strong> {{REASON}}
    </div>
    <div class="contact">
      <p style="margin-bottom: 0;">If this is a mistake or you would like to start official collaboration, please contact <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></p>
    </div>
  </div>
</body>
</html>`;

// Challenge page — served with 403 for challenge-eligible blocks. The widget
// JS loads from Cloudflare's CDN (reachable — only OUR origin blocks the
// client); on success the page reloads the SAME URL with the token appended
// (this 403 body renders at the URL the user requested, so location.href IS
// the original URL). No-JS clients still get the reason + contact fallback.
const CHALLENGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>One more step</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
      max-width: 520px;
      width: 100%;
      padding: 48px 40px;
      text-align: center;
    }
    .icon { font-size: 64px; margin-bottom: 24px; }
    h1 { color: #1a202c; font-size: 24px; font-weight: 700; margin-bottom: 16px; }
    p { color: #4a5568; font-size: 16px; line-height: 1.6; margin-bottom: 20px; }
    .widget {
      display: flex;
      justify-content: center;
      min-height: 66px;
      margin-bottom: 24px;
    }
    .reason {
      background: #f7fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 24px;
      font-family: monospace;
      font-size: 12px;
      color: #718096;
      word-break: break-all;
      text-align: left;
    }
    .contact { background: #f7fafc; border-radius: 12px; padding: 20px; font-size: 14px; }
    .contact a { color: #667eea; text-decoration: none; font-weight: 600; }
    .contact a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#128075;</div>
    <h1>Quick check &mdash; are you human?</h1>
    <p>Your browser matched a pattern our bot protection watches for.
       Complete the check below and you'll continue straight to the page.</p>
    <div class="widget">
      <div class="cf-turnstile" data-sitekey="${TURNSTILE_SITE_KEY}" data-callback="__bbSolved"></div>
    </div>
    <div class="reason"><strong>Matched rule:</strong> {{REASON}}</div>
    <div class="contact">
      <p style="margin-bottom: 0;">No luck, or no JavaScript? Email <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a> and we'll sort it out.</p>
    </div>
  </div>
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
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</body>
</html>`;

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
  handleRequest(req, res).catch((err) => {
    console.error(`[ERROR] handler failed open: ${err.stack || err.message}`);
    if (!res.headersSent) {
      res.writeHead(200);
    }
    res.end('OK');
  });
});

async function handleRequest(req, res) {
  const userAgent = req.headers['x-forwarded-user-agent'] || req.headers['user-agent'] || '';
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const requestPath = req.headers['x-forwarded-uri'] || req.url || '/';
  const originalProtocol = req.headers['x-original-protocol'] || '';

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
  const whitelisted = await checkWhitelistedBot(userAgent, ip);
  if (whitelisted) {
    if (whitelisted.allow) {
      res.writeHead(200);
      res.end('OK');
      return;
    }
    if (whitelisted.capped) {
      logBlocked('crawler_capped', ip, userAgent,
        `${whitelisted.name} over ${WHITELIST_BOT_CAP}/min per-IP crawler cap`, requestPath);
      res.writeHead(429, {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After': '60',
        'X-Blocked-Reason': 'crawler_cap',
      });
      res.end(RATE_LIMITED_HTML);
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
    res.writeHead(200);
    res.end('OK');
    return;
  }

  // A valid pass cookie bypasses ONLY the challenge-eligible heuristics below
  // (UA signatures, the 43/8 combo). Hard rules, rate limits and scrape
  // detection still apply to cookie holders. Permabans need no bypass —
  // solving the challenge lifted them.
  const hasPass = CHALLENGE_ENABLED && hasValidPassCookie(req.headers['cookie'], ip);

  // Check permanent ban
  if (isPermanentlyBanned(ip)) {
    const info = bannedIPs.get(ip);
    logBlocked('permaban', ip, userAgent, info.reason, requestPath);
    serveChallengeOrBlock(res, `Permanently banned: ${info.reason}`, 'permaban');
    return;
  }

  // Check blocked paths
  for (const { pattern, reason } of BLOCKED_PATHS) {
    if (pattern.test(requestPath)) {
      logBlocked('path', ip, userAgent, reason, requestPath);

      const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);

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
        serveChallengeOrBlock(res, reason, reason);
        return;
      }

      const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);

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
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);
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
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, subnetBlock);
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
    serveChallengeOrBlock(res, reason, 'chinese_botnet');
    return;
  }

  // Check fake iOS bot from Chinese cloud
  if (isFakeIOSBot(ip, userAgent)) {
    const reason = 'Fake iOS bot from Chinese cloud';
    logBlocked('botnet', ip, userAgent, reason, requestPath);
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);
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
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);
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
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);
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
      serveChallengeOrBlock(res, `Permanently banned: ${scrapeResult.reason}`, 'page_scrape_ban');
      return;
    } else {
      logBlocked('page_scrape', ip, userAgent,
        `Strike ${scrapeResult.strikes}/${SCRAPE_STRIKES_FOR_BAN}: ${scrapeResult.reason}`, requestPath);

      res.writeHead(429, {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After': '300',
        'X-Blocked-Reason': 'page_scrape',
      });
      res.end(RATE_LIMITED_HTML);
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
    res.end(RATE_LIMITED_HTML);
    return;
  }

  // Risk-scoring ladder (D50) — the LAST gate, after every deterministic rule
  // passed. Scores the anonymous HTML surface; above the threshold it serves
  // the Turnstile challenge (managed mode: invisible to genuine browsers).
  // Pass-cookie holders already proved humanity — never re-scored within the
  // cookie's lifetime. In 'log' (shadow) mode nothing is ever acted on.
  if (SCORING_MODE !== 'off' && !hasPass && isScorableRequest(req.headers, requestPath)) {
    const rate5m = surgeTick();
    const risk = computeRiskScore(ip, userAgent, requestPath, req.headers, rate5m);
    if (risk.score >= SCORE_THRESHOLD) {
      const detail = `Risk score ${risk.score} (base ${risk.base} × pressure ${risk.pressure})`;
      // Challenge only when the challenge stack is live — a heuristic score
      // must NEVER produce a hard 403, so without Turnstile keys we shadow-log.
      if (SCORING_MODE === 'challenge' && CHALLENGE_ENABLED) {
        logBlocked('risk_challenge', ip, userAgent, detail, requestPath, risk);
        serveChallengeOrBlock(res, 'Automated traffic suspected', 'risk_score');
        return;
      }
      logBlocked('risk_shadow', ip, userAgent, detail, requestPath, risk);
    } else if (risk.score >= SCORE_LOG_MIN) {
      // Sub-threshold observability: the shadow phase tunes the threshold
      // from this distribution instead of guessing.
      logBlocked('risk_observe', ip, userAgent, `Risk score ${risk.score}`, requestPath, risk);
    }
  }

  // Allow request
  res.writeHead(200);
  res.end('OK');
}

// =============================================================================
// STARTUP
// =============================================================================

// Guarded so tests can `require('./server.js')` and exercise the helpers
// without starting the server or touching the log directory.
if (require.main === module) {

ensureLogDir();
loadBannedIPs();
initGeoDb(GEODB_DIR);

server.listen(PORT, () => {
  console.log(`Bot blocker middleware running on port ${PORT}`);
  console.log(`Rate limit: ${RATE_LIMIT} requests per ${RATE_WINDOW / 1000}s`);
  console.log(`Challenge: ${CHALLENGE_ENABLED ? `ENABLED (cookie TTL ${CHALLENGE_COOKIE_TTL_MS / 86400000}d)` : 'disabled (missing TURNSTILE_SITE_KEY/TURNSTILE_SECRET_KEY/CHALLENGE_COOKIE_SECRET or CHALLENGE_ENABLED=false)'}`);
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
  console.log(`Log directory: ${LOG_DIR}`);
  console.log(`Contact email: ${CONTACT_EMAIL}`);
  scheduleNextSummary();
});

} // require.main guard

// Exported for unit tests only — the module never gets required in production.
module.exports = {
  server,
  signPassCookie,
  buildRedirectUrl,
  makePassCookie,
  hasValidPassCookie,
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
  // Crawler verification
  checkWhitelistedBot,
  verifyCrawlerRdns,
  _setDnsForTests,
  isCrawlerCapped,
  WHITELIST_BOT_CAP,
};
