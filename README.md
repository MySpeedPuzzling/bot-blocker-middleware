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
