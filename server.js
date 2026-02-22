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
  { pattern: /Baiduspider/i, name: 'Baidu' },
  { pattern: /Slurp/i, name: 'Yahoo' },
  { pattern: /Sogou/i, name: 'Sogou' },
  { pattern: /Applebot/i, name: 'Apple (Siri/Spotlight)' },
  { pattern: /Qwant/i, name: 'Qwant' },

  // Social media previews (important for link sharing/SEO)
  { pattern: /facebookexternalhit/i, name: 'Facebook' },
  { pattern: /Twitterbot/i, name: 'Twitter/X' },
  { pattern: /LinkedInBot/i, name: 'LinkedIn' },
  { pattern: /WhatsApp/i, name: 'WhatsApp' },
  { pattern: /Slackbot/i, name: 'Slack' },
  { pattern: /TelegramBot/i, name: 'Telegram' },
  { pattern: /Discordbot/i, name: 'Discord' },
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
 * Detects Chinese botnet based on combination of IP, protocol, and user agent
 * Pattern: 43.x IP + HTTP/1.1 + Windows 10 + Chrome 100-139
 */
function isChineseBotnet(ip, userAgent, httpVersion) {
  if (!ip || !ip.startsWith('43.')) return false;
  if (httpVersion !== '1.1') return false;
  const botPattern = /Windows NT 10\.0.*Chrome\/(10[0-9]|11[0-9]|12[0-9]|13[0-9])\./;
  return botPattern.test(userAgent || '');
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
// RATE LIMITING
// =============================================================================

function isRateLimited(ip) {
  const now = Date.now();

  if (!requests.has(ip)) {
    requests.set(ip, { count: 1, windowStart: now });
    return false;
  }

  const record = requests.get(ip);

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
  if (isChineseBotnet(ip, userAgent, req.httpVersion)) {
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

  // Check rate limit
  if (isRateLimited(ip)) {
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
  console.log(`Banned IPs loaded: ${bannedIPs.size}`);
  console.log(`Whitelisted bot patterns: ${WHITELISTED_BOTS.length}`);
  console.log(`Blocked bot patterns: ${BLOCKED_BOTS.length}`);
  console.log(`Blocked CIDR subnets: ${BLOCKED_CIDRS.length}`);
  console.log(`Static asset patterns: ${STATIC_ASSET_PATTERNS.length}`);
  console.log(`Log directory: ${LOG_DIR}`);
  console.log(`Contact email: ${CONTACT_EMAIL}`);
  scheduleNextSummary();
});
