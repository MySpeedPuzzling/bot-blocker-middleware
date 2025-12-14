# Bot Blocker Middleware

Traefik ForwardAuth middleware for blocking bots and rate limiting requests.

## Features

- Rate limiting (45 req/min per IP by default)
- Bot detection via user agent patterns
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
      - RATE_LIMIT=45
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
| `RATE_LIMIT` | `45`                   | Max requests per window |
| `RATE_WINDOW` | `60000`                | Window size in ms (1 min) |
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

## Log Files

```
/var/log/bot-blocker/
├── blocked-2025-12-07.log    # Daily JSON logs
└── summary-2025-12-06.txt    # Auto-generated summaries
```

View logs:
```bash
docker compose logs bot-blocker
cat ./bot-blocker-logs/blocked-$(date +%Y-%m-%d).log | jq .
```
