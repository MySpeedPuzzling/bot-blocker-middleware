const http = require('http');
const fs = require('fs');
const path = require('path');

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONTACT_EMAIL = process.env.CONTACT_EMAIL || 'j.mikes@me.com';
const LOG_DIR = process.env.LOG_DIR || '/var/log/bot-blocker';
const PORT = process.env.PORT || 3000;
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT, 10) || 30;
const RATE_WINDOW = parseInt(process.env.RATE_WINDOW, 10) || 60 * 1000; // 1 minute

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
// BLOCKED BOT PATTERNS
// Add new patterns here to expand blocking
// =============================================================================

const BLOCKED_BOTS = [
  // Chinese bots
  { pattern: /AliyunSecBot/i, reason: 'Chinese security scanner bot' },
  { pattern: /PetalBot/i, reason: 'Huawei search engine bot' },

  // SEO scrapers
  { pattern: /SemrushBot/i, reason: 'SEO scraper bot' },
  { pattern: /AhrefsBot/i, reason: 'SEO scraper bot' },
  { pattern: /DotBot/i, reason: 'SEO scraper bot' },
  { pattern: /MJ12bot/i, reason: 'SEO scraper bot' },

  // Impossible browser combinations (spoofed user agents)
  { pattern: /Windows NT 6\.1.*Chrome\/12[0-9]/i, reason: 'Impossible browser: Windows 7 + Chrome 120+' },
  { pattern: /Windows NT 6\.1.*Chrome\/13[0-9]/i, reason: 'Impossible browser: Windows 7 + Chrome 130+' },
  { pattern: /Windows NT 6\.1.*Chrome\/14[0-9]/i, reason: 'Impossible browser: Windows 7 + Chrome 140+' },
  { pattern: /iPad; CPU iPad OS 1_/i, reason: 'Impossible browser: iPad OS 1.x does not exist' },
  { pattern: /iPhone OS 26_/i, reason: 'Impossible browser: iOS 26 does not exist' },
];

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

// Cleanup old rate limit records every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of requests) {
    if (now - record.windowStart > RATE_WINDOW * 2) {
      requests.delete(key);
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

server.listen(PORT, () => {
  console.log(`Bot blocker middleware running on port ${PORT}`);
  console.log(`Rate limit: ${RATE_LIMIT} requests per ${RATE_WINDOW / 1000}s`);
  console.log(`Blocked bot patterns: ${BLOCKED_BOTS.length}`);
  console.log(`Static asset patterns: ${STATIC_ASSET_PATTERNS.length}`);
  console.log(`Log directory: ${LOG_DIR}`);
  console.log(`Contact email: ${CONTACT_EMAIL}`);
  scheduleNextSummary();
});
