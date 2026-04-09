const http = require('http');
const fs = require('fs');
const path = require('path');

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONTACT_EMAIL = process.env.CONTACT_EMAIL || 'j.mikes@me.com';
const LOG_DIR = process.env.LOG_DIR || '/var/log/bot-blocker';
const PORT = process.env.PORT || 3000;
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT, 10) || 45;
const RATE_WINDOW = parseInt(process.env.RATE_WINDOW, 10) || 60 * 1000; // 1 minute

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
  /^\/site\.webmanifest$/i,
  /^\/apple/i,
  /^\/mstile/i,
  /^\/safari/i,
];

function isStaticAsset(requestPath) {
  return STATIC_ASSET_PATTERNS.some(pattern => pattern.test(requestPath));
}

// =============================================================================
// SEARCH ENGINE BOT WHITELIST (bypass all blocking)
// =============================================================================

const WHITELISTED_BOTS = [
  // Google (https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers)
  { pattern: /Googlebot/i, name: 'Googlebot' },
  { pattern: /Google-InspectionTool/i, name: 'Google Search Console' },
  { pattern: /Storebot-Google/i, name: 'Google Merchant' },
  { pattern: /AdsBot-Google/i, name: 'Google Ads' },
  { pattern: /Mediapartners-Google/i, name: 'Google AdSense' },
  { pattern: /APIs-Google/i, name: 'Google APIs' },
  { pattern: /GoogleOther/i, name: 'Google Other' },

  // Bing / Microsoft
  { pattern: /bingbot/i, name: 'Bingbot' },
  { pattern: /msnbot/i, name: 'MSN Bot' },
  { pattern: /AdIdxBot/i, name: 'Microsoft Advertising' },
  { pattern: /BingPreview/i, name: 'Bing Preview' },

  // Other search engines
  { pattern: /YandexBot/i, name: 'Yandex' },
  { pattern: /DuckDuckBot/i, name: 'DuckDuckGo' },
  { pattern: /Slurp/i, name: 'Yahoo' },
  { pattern: /Applebot/i, name: 'Apple (Siri/Spotlight)' },
  { pattern: /Qwant/i, name: 'Qwant' },
  { pattern: /SeznamBot/i, name: 'Seznam' },

  // Social media previews (important for link sharing/SEO)
  { pattern: /facebookexternalhit/i, name: 'Facebook' },
  { pattern: /meta-externalagent/i, name: 'Meta (external agent)' },
  { pattern: /meta-webindexer/i, name: 'Meta (web indexer)' },
  { pattern: /Twitterbot/i, name: 'Twitter/X' },
  { pattern: /LinkedInBot/i, name: 'LinkedIn' },
  { pattern: /WhatsApp/i, name: 'WhatsApp' },
  { pattern: /Slackbot/i, name: 'Slack' },
  { pattern: /TelegramBot/i, name: 'Telegram' },
  { pattern: /Discordbot/i, name: 'Discord' },

  // Monitoring
  { pattern: /SentryUptimeBot/i, name: 'Sentry Uptime' },
  { pattern: /Stripe\//i, name: 'Stripe' },
];

function isWhitelistedBot(userAgent) {
  if (!userAgent) return false;
  for (const { pattern, name } of WHITELISTED_BOTS) {
    if (pattern.test(userAgent)) return name;
  }
  return false;
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
    // =========================================================================

    // Opera Presto engine discontinued in 2013 — all modern Opera uses Chromium
    { pattern: /Presto\/\d/i, reason: 'Fake Opera bot (Presto engine discontinued 2013)' },

    // =========================================================================
    // IMPOSSIBLE BROWSER COMBINATIONS (verified safe)
    // =========================================================================

    // Windows 7 (NT 6.1) + Chrome 110+ is impossible
    // Chrome 109 was the LAST version supporting Windows 7 (February 2023)
    // Source: Google officially ended support
    { pattern: /Windows NT 6\.1.*Chrome\/1[1-9][0-9]\./i, reason: 'Impossible: Windows 7 + Chrome 110+ (support ended Feb 2023)' },
    { pattern: /Windows NT 6\.1.*Chrome\/[2-9][0-9]{2}\./i, reason: 'Impossible: Windows 7 + Chrome 200+' },

    // Windows Vista (NT 6.0) + Chrome 50+ is impossible
    // Chrome 49 was the LAST version supporting Vista (April 2016)
    { pattern: /Windows NT 6\.0.*Chrome\/[5-9][0-9]\./i, reason: 'Impossible: Windows Vista + Chrome 50+' },
    { pattern: /Windows NT 6\.0.*Chrome\/1[0-9]{2}\./i, reason: 'Impossible: Windows Vista + Chrome 100+' },

    // Windows XP (NT 5.1) + Chrome 50+ is impossible
    // Chrome 49 was the LAST version supporting XP (April 2016)
    { pattern: /Windows NT 5\.1.*Chrome\/[5-9][0-9]\./i, reason: 'Impossible: Windows XP + Chrome 50+' },
    { pattern: /Windows NT 5\.1.*Chrome\/1[0-9]{2}\./i, reason: 'Impossible: Windows XP + Chrome 100+' },
];

// =============================================================================
// CIDR BLOCKLIST (known botnet subnets)
// =============================================================================

const BLOCKED_CIDRS = [
  { prefix: '43.104.33.', reason: 'Known Chinese botnet subnet' },
  // 43.173.168.0/21 covers 43.173.168-175.x
  { prefix: '43.173.168.', reason: 'Known Chinese botnet subnet' },
  { prefix: '43.173.169.', reason: 'Known Chinese botnet subnet' },
  { prefix: '43.173.170.', reason: 'Known Chinese botnet subnet' },
  { prefix: '43.173.171.', reason: 'Known Chinese botnet subnet' },
  { prefix: '43.173.172.', reason: 'Known Chinese botnet subnet' },
  { prefix: '43.173.173.', reason: 'Known Chinese botnet subnet' },
  { prefix: '43.173.174.', reason: 'Known Chinese botnet subnet' },
  { prefix: '43.173.175.', reason: 'Known Chinese botnet subnet' },
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

function logBlocked(type, ip, userAgent, reason, requestPath) {
  const timestamp = new Date().toISOString();
  const logEntry = { timestamp, type, ip, userAgent, reason, path: requestPath };
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
// CHROME VERSION SPAN DETECTION (catches UA rotation bots)
// =============================================================================

const CHROME_SPAN_WINDOW = 10 * 60 * 1000;  // 10 minutes
const CHROME_SPAN_THRESHOLD = 10;            // version difference that triggers block
const chromeVersionTracker = new Map();      // ip -> { minVersion, maxVersion, windowStart }

/**
 * Detects UA rotation bots by tracking Chrome version spread per IP.
 * Bots rotate: Chrome/103, Chrome/111, Chrome/146 (span = 43 → blocked).
 * Real users at competition: all have Chrome/145-146 (span = 1 → allowed).
 * Chrome auto-updates enforce version convergence on same network.
 */
function checkChromeVersionSpan(ip, userAgent) {
  if (!userAgent) return false;

  // Only track Windows 10 + Chrome user agents
  const match = userAgent.match(/Windows NT 10\.0.*Chrome\/(\d+)\./);
  if (!match) return false;

  const version = parseInt(match[1], 10);
  const now = Date.now();

  if (!chromeVersionTracker.has(ip)) {
    chromeVersionTracker.set(ip, { minVersion: version, maxVersion: version, windowStart: now });
    return false;
  }

  const record = chromeVersionTracker.get(ip);

  // Reset window if expired
  if (now - record.windowStart > CHROME_SPAN_WINDOW) {
    record.minVersion = version;
    record.maxVersion = version;
    record.windowStart = now;
    return false;
  }

  // Update min/max
  if (version < record.minVersion) record.minVersion = version;
  if (version > record.maxVersion) record.maxVersion = version;

  return (record.maxVersion - record.minVersion) >= CHROME_SPAN_THRESHOLD;
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

  // Clean chrome version span tracker
  for (const [key, record] of chromeVersionTracker) {
    if (now - record.windowStart > CHROME_SPAN_WINDOW * 2) {
      chromeVersionTracker.delete(key);
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
}, 5 * 60 * 1000);

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

// =============================================================================
// HTTP SERVER
// =============================================================================

const server = http.createServer((req, res) => {
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

  // Whitelist search engine bots and social media crawlers - bypass all blocking
  const whitelistedBotName = isWhitelistedBot(userAgent);
  if (whitelistedBotName) {
    res.writeHead(200);
    res.end('OK');
    return;
  }

  // Check permanent ban
  if (isPermanentlyBanned(ip)) {
    const info = bannedIPs.get(ip);
    logBlocked('permaban', ip, userAgent, info.reason, requestPath);

    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g,
      `Permanently banned: ${info.reason}`);

    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'permaban',
    });
    res.end(html);
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
  for (const { pattern, reason } of BLOCKED_BOTS) {
    if (pattern.test(userAgent)) {
      logBlocked('bot', ip, userAgent, reason, requestPath);

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

  // Check Chinese botnet (combination detection)
  if (isChineseBotnet(ip, userAgent)) {
    const reason = 'Chinese cloud botnet (43.x + HTTP/1.1 + outdated Chrome)';
    logBlocked('botnet', ip, userAgent, reason, requestPath);
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'chinese_botnet',
    });
    res.end(html);
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

  // Check Chrome version span (UA rotation detection)
  if (checkChromeVersionSpan(ip, userAgent)) {
    const reason = 'UA rotation detected: multiple Chrome versions from same IP';
    logBlocked('ua_rotation', ip, userAgent, reason, requestPath);
    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, reason);
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'ua_rotation',
    });
    res.end(html);
    return;
  }

  // Check locale switching (may trigger permanent ban)
  if (checkLocaleSwitch(ip, requestPath)) {
    const info = bannedIPs.get(ip);
    logBlocked('locale_switch', ip, userAgent, info.reason, requestPath);

    const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g, info.reason);

    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Blocked-Reason': 'locale_switch',
    });
    res.end(html);
    return;
  }

  // Check page scraping (puzzle/profile) — progressive: 429 on 1st/2nd strike, permaban on 3rd
  const scrapeResult = checkPageScraping(ip, userAgent, requestPath);
  if (scrapeResult) {
    if (scrapeResult.banned) {
      logBlocked('page_scrape_ban', ip, userAgent, scrapeResult.reason, requestPath);

      const html = BOT_BLOCKED_HTML.replace(/\{\{REASON\}\}/g,
        `Permanently banned: ${scrapeResult.reason}`);

      res.writeHead(403, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Blocked-Reason': 'page_scrape_ban',
      });
      res.end(html);
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

  // Allow request
  res.writeHead(200);
  res.end('OK');
});

// =============================================================================
// STARTUP
// =============================================================================

ensureLogDir();
loadBannedIPs();

server.listen(PORT, () => {
  console.log(`Bot blocker middleware running on port ${PORT}`);
  console.log(`Rate limit: ${RATE_LIMIT} requests per ${RATE_WINDOW / 1000}s`);
  console.log(`Locale detection: ${LOCALE_THRESHOLD} locales with ${LOCALE_MIN_HITS}+ hits each in ${LOCALE_WINDOW / 1000}s triggers ${BAN_DURATION / (24 * 60 * 60 * 1000)}-day ban`);
  console.log(`Page scrape detection: ${PUZZLE_SCRAPE_THRESHOLD} puzzles/${PUZZLE_SCRAPE_WINDOW / 1000}s, ${PROFILE_SCRAPE_THRESHOLD} profiles/${PROFILE_SCRAPE_WINDOW / 1000}s, ${SCRAPE_STRIKES_FOR_BAN} strikes to ban`);
  console.log(`Chrome version span: threshold=${CHROME_SPAN_THRESHOLD} versions, window=${CHROME_SPAN_WINDOW / 1000}s`);
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
