# Bot Blocker Middleware

Traefik ForwardAuth middleware for blocking bots and rate limiting requests.

## Features

- Rate limiting (60 req/min per IP by default)
- Bot detection via user agent patterns
- Chinese botnet detection (IP + HTTP version + outdated browser combo)
- CIDR subnet blocking for known malicious IP ranges
- Locale scraping detection (auto-bans IPs switching locales rapidly)
- Permanent IP banning with 30-day expiry
- Static assets excluded from rate limiting
- Daily log rotation with summaries
- User-friendly block pages

## Quick Start

### Docker Compose

```yaml
services:
  bot-blocker:
    image: ghcr.io/myspeedpuzzling/bot-blocker-middleware:latest
    restart: always
    environment:
      - RATE_LIMIT=60
      - CONTACT_EMAIL=your@email.com
    volumes:
      - ./bot-blocker-logs:/var/log/bot-blocker
    networks:
      - traefik
```

### Traefik Configuration

Add to your `dynamic-config.yml`:

```yaml
http:
  middlewares:
    bot-blocker:
      forwardAuth:
        address: "http://bot-blocker:3000"
        trustForwardHeader: true
```

Apply to a router:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=bot-blocker@file"
```

## Environment Variables

| Variable | Default                | Description |
|----------|------------------------|-------------|
| `PORT` | `3000`                 | Server port |
| `RATE_LIMIT` | `60`                   | Max requests per window |
| `RATE_WINDOW` | `60000`                | Window size in ms (1 min) |
| `LOCALE_THRESHOLD` | `4`                    | Unique locales to trigger ban |
| `LOCALE_MIN_HITS` | `3`                    | Min requests per locale |
| `LOCALE_WINDOW` | `60000`                | Detection window in ms |
| `BAN_DURATION` | `2592000000`           | Ban duration in ms (30 days) |
| `CONTACT_EMAIL` | `j.mikes@me.com`       | Contact email on block pages |
| `LOG_DIR` | `/var/log/bot-blocker` | Log directory |
| `TURNSTILE_SITE_KEY` | *(empty)* | Cloudflare Turnstile site key — challenge disabled while empty |
| `TURNSTILE_SECRET_KEY` | *(empty)* | Turnstile secret key for siteverify |
| `CHALLENGE_COOKIE_SECRET` | *(empty)* | HMAC secret signing the pass cookie |
| `CHALLENGE_COOKIE_TTL_DAYS` | `7` | How long a solved challenge holds |
| `CHALLENGE_VERIFY_LIMIT` | `5` | siteverify attempts per IP per minute |
| `CHALLENGE_ENABLED` | `true` | Kill switch (`false` disables even with keys set) |
| `TRUST_COOKIE_SECRET` | *(=CHALLENGE_COOKIE_SECRET)* | HMAC secret validating the app-issued `__bb_trust` cookie |
| `TRUST_COOKIE_TTL_DAYS` | `365` | Max age of a trust cookie (from its embedded issued-at) |
| `SCORING_MODE` | `log` | Risk ladder: `off` / `log` (shadow) / `challenge` |
| `SCORE_THRESHOLD` | `60` | Score at/above which the ladder challenges |
| `SCORE_LOG_MIN` | `25` | Scores ≥ this are logged even below the threshold |
| `HIGH_RISK_COUNTRIES` | `CN,HK,SG,VN,ID` | Audience-prior country list (comma-separated ISO codes) |
| `SURGE_BASELINE_5M` | `300` | Calm-traffic scorable requests per 5 min (pressure = rate/baseline) |
| `SURGE_EXTRA_SCORE` | `20` | Extra base score for locale+cookieless requests while pressure > 2× |
| `WHITELIST_BOT_CAP` | `30` | Per-IP req/min cap for UA-only whitelisted crawlers |
| `RDNS_TIMEOUT_MS` | `1500` | Timeout per rDNS lookup step (fail-open on expiry) |
| `GOOGLE_RANGES_REFRESH_HOURS` | `24` | Runtime refresh of Google's published crawler/fetcher IP lists (0 = baked copy only) |
| `GEODB_DIR` | `./geodb` | Directory with the DB-IP binary range files |

## Human-Recovery Challenge (Cloudflare Turnstile)

Heuristic rules that could plausibly catch a real human serve a **403 challenge
page** (Turnstile widget) instead of a flat block. Solving it sets an
HMAC-signed, **IP-bound** pass cookie (`__bb_pass`, default 7 days) and lifts
any active permaban for that IP. The challenge auto-disables unless
`TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` and `CHALLENGE_COOKIE_SECRET` are
all set — deploying without them changes nothing.

**Challenge-eligible** (UA signatures real humans can hit via privacy tools /
Opera Mini / anti-fingerprinting randomizers, plus the broad 43/8 combo and
permaban pages):

- Dead device (Nexus 5 / Android 6)
- All "Impossible: OS + Chrome version" combos, fake Chrome 48, fake Opera Presto
- Chinese cloud botnet combo (43.x + Windows 10 + Chrome)
- Permanent-ban page (locale scraping, page-scraping strikes) — solving unbans

**Never challenge-eligible:** named bots (GPTBot, ClaudeBot, SemrushBot, …),
exploit paths (`wp-*`, `.env`, `.git`), curated botnet subnets, HeadlessChrome —
and the **behavioral rules (rate limit, scrape strikes) are never bypassed by
the cookie**: the challenge proves a human is present, not that the traffic
volume is acceptable. A cookie holder who trips a behavioral ban gets challenged
again; each solve costs the scraper another widget per exit IP.

Flow (shaped by forwardAuth constraints — Traefik forwards request *headers*
only, and returns our full response to the client on non-2xx):

1. Eligible block → 403 challenge page at the original URL
2. Solved widget reloads the same URL with `?__bb_token=<token>` (query string —
   a POST body would never reach the middleware)
3. Middleware verifies via siteverify (5s timeout, fails closed), replies
   `302` + `Set-Cookie` back to the clean URL
4. The cookie arrives in forwarded headers on every later request

`challenge_passed` entries in the daily JSONL log are the **measured
false-positive rate** of the challenge-eligible rules.

## Trusted-Human Cookie (`__bb_trust`)

The MySpeedPuzzling app mints an HMAC-signed cookie on authenticated
responses (`BotTrustCookieSubscriber` + `BotTrustCookieSigner` in the app
repo); this middleware only validates it. A valid cookie is a **full bypass**
— including permabans and rate limits (competition venues put 1000+ real
users behind one WiFi IP). It is deliberately **not** IP-bound: phones roam.
Format: `base64url("bb-trust|v1|<uid>|<iatMs>") + "." + base64url(hmac)`,
signed with `CHALLENGE_COOKIE_SECRET` (domain-separated from `__bb_pass`).
Both repos pin the wire format with the same golden-vector test.

## Risk-Scoring Ladder

For anonymous HTML GETs that pass every deterministic rule, a per-request
score is computed from weak signals — datacenter ASN (GeoDB), audience-prior
country, impossible-Chromium header sets (missing `Sec-Fetch-*`/`sec-ch-ua`,
platform contradicting the UA), missing/mismatched `Accept-Language`, and
cookie-persistence anomalies — multiplied by global crawl **pressure**
(current rate vs `SURGE_BASELINE_5M`, capped 2.5×), so the ladder tightens
itself during a distributed crawl and relaxes after. At/above
`SCORE_THRESHOLD` the request gets the **Turnstile challenge** (never a hard
block); solving sets the standard pass cookie. `SCORING_MODE=log` (default)
only writes `risk_shadow`/`risk_observe` JSONL entries with full component
breakdowns — deploy in shadow, tune the threshold from real data, then flip
to `challenge`.

Built against the 2026-07/08 residential-proxy swarm: 15k IPs/3.4 days, 89%
seen a single day (per-IP counters useless), flawless Chrome UAs over h2/h3,
executing Google Analytics from worldwide consumer ISPs.

## Verified Crawler Whitelist

Crawlers are verified two ways, because not every operator publishes the same
proof:

- **rDNS** — `Googlebot`/`Bingbot`/`SeznamBot`/`YandexBot`/`Applebot`, forward
  confirmed and cached 48 h. DNS trouble fails **open**; a definitive mismatch
  falls through to the normal pipeline as a fake.
- **ASN** — `facebookexternalhit`/`meta-externalagent`/`meta-webindexer`, by
  membership of AS32934 (`geodb/crawler-asn.bin`). Meta's fetchers have **no
  PTR records at all**, so the rDNS check could only ever call them fake — it
  did, for 50 583 requests in 48 h, which silently broke Facebook/WhatsApp
  link previews. Missing range data or an IPv6 client fails **open** to the
  capped UA-only path, never to fake.

UA-only entries (other link-preview bots) and both verified Meta paths pass
under a `WHITELIST_BOT_CAP`/min per-IP budget. Stripe stays uncapped — webhook
delivery must never break.

## GeoDB (DB-IP)

`scripts/build-geodb.mjs` compiles the free DB-IP lite databases plus the
verified-crawler ASN prefixes (RIPEstat) into binary range files at image
build; a monthly scheduled CI rebuild keeps them fresh. Missing files degrade
gracefully (geo/ASN signals score 0, ASN-verified crawlers fall back to
capped).
*IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0).*

## Adding New Bot Patterns

Edit `server.js` and add patterns to `BLOCKED_BOTS` array:

```javascript
const BLOCKED_BOTS = [
  { pattern: /YourBotName/i, reason: 'Description of why blocked' },
  // ... existing patterns
];
```

## Chinese Botnet Detection

Blocks distributed botnets from Chinese cloud providers (Alibaba, Tencent) that evade per-IP rate limiting by rotating through hundreds of IPs.

**Detection methods:**

1. **CIDR blocklist** - Known malicious subnets (43.104.33.0/24, 43.173.168.0/21)
2. **Combination detection** - Blocks requests matching ALL of:
   - IP starts with `43.`
   - HTTP/1.1 protocol (bots don't use HTTP/2)
   - Windows 10 + Chrome 100-139 (outdated versions)
3. **Fake iOS detection** - Blocks 43.x IPs with ancient iOS 13.2.3 user agents

## Locale Scraping Detection

Automatically bans IPs that access multiple locale paths rapidly (e.g., scraping `/en/`, `/de/`, `/fr/`, `/es/`, `/ja/` versions).

**Trigger:** 4+ unique locales with 3+ requests each within 60 seconds = 30-day ban

**Persistence:** Banned IPs stored in `banned-ips.json` (survives restarts)

## Log Files

```
/var/log/bot-blocker/
├── blocked-2025-12-07.log    # Daily JSON logs
├── summary-2025-12-06.txt    # Auto-generated summaries
└── banned-ips.json           # Persistent IP bans
```

View logs:
```bash
docker compose logs bot-blocker
cat ./bot-blocker-logs/blocked-$(date +%Y-%m-%d).log | jq .
```
