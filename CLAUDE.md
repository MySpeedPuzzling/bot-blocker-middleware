# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Bot Blocker Middleware is a Traefik ForwardAuth middleware for blocking bots and rate limiting requests. It's a single-file Node.js HTTP server (`server.js`) that integrates with Traefik's forward authentication.

## Commands

```bash
npm start          # Start the server (runs node server.js)
```

No build step, linting, or tests are configured.

## Architecture

The middleware receives forwarded requests from Traefik and decides whether to allow (200) or block (403/429) them.

**Request flow:**
1. Static asset check → bypass rate limiting for `/build/`, `/css/`, `/img/`, etc.
2. Search engine bot whitelist → immediate 200 for Googlebot, Bingbot, YandexBot, DuckDuckBot, social media crawlers, etc.
3. Permanent ban check → immediate 403 for banned IPs
4. Blocked path check → immediate 403 for WordPress exploits, `.env`, `.git` access
5. Bot detection → 403 for known bad user agents (SEO bots, AI crawlers, impossible browser combos)
6. CIDR subnet check → 403 for known malicious IP ranges (43.104.33.0/24, 43.173.168.0/21)
7. Chinese botnet check → 403 for 43.x IPs + Windows 10 + Chrome (any version)
8. Fake iOS bot check → 403 for 43.x IPs with iPhone OS 13_2_3
9. Cloud botnet check → 403 for HTTP/1.1 + Windows Chrome + cloud provider IPs (requires Traefik plugin)
10. Chrome version span check → 403 if same IP sends 3+ Chrome versions spanning 10+ apart in 10 min
11. Locale switching check → 403 + permaban if 4 locales with 3+ hits in 60s
12. Page scraping check → 429/403 for rapid puzzle/profile page scraping (IP+UA keyed)
13. Rate limiting → 429 if IP+UA exceeds `RATE_LIMIT` requests per `RATE_WINDOW`
14. Allow → 200 OK

**Key data structures in `server.js`:**
- `STATIC_ASSET_PATTERNS` - regex array for paths excluded from rate limiting
- `WHITELISTED_BOTS` - objects with `pattern` and `name` for search engine/social media bot whitelisting
- `BLOCKED_PATHS` - objects with `pattern` and `reason` for malicious path detection
- `BLOCKED_BOTS` - objects with `pattern` and `reason` for user agent blocking
- `BLOCKED_CIDRS` - objects with `prefix` and `reason` for subnet blocking
- `CLOUD_PROVIDER_CIDRS` - CIDR ranges for BytePlus, Tencent Cloud, Alibaba Cloud (proper bitmask matching)
- `isChineseBotnet()` - detects 43.x + Windows 10 + Chrome (any version)
- `isCloudBotnet()` - detects cloud IP + HTTP/1.1 + Windows Chrome (requires X-Original-Protocol header)
- `checkChromeVersionSpan()` - detects UA rotation by tracking Chrome version spread per IP
- `isFakeIOSBot()` - detects 43.x + ancient iOS user agents
- `requests` Map - in-memory rate limit tracking per IP+UA
- `bannedIPs` Map - persisted permanent bans (loaded from `banned-ips.json`)
- `localeTracker` Map - in-memory locale switching detection per IP
- `chromeVersionTracker` Map - tracks min/max Chrome versions per IP for rotation detection

**Traefik headers used:**
- `X-Forwarded-For` - client IP
- `X-Forwarded-User-Agent` - original user agent
- `X-Forwarded-URI` - original request path
- `X-Original-Protocol` - original HTTP protocol version (from Traefik plugin, e.g. `HTTP/2.0`)

**Rate limiting is keyed by IP+UA** (not IP-only) because during puzzle competitions, 1000+ users share the same WiFi/IP. IP-only rate limiting would block all attendees.

## Traefik Plugin

The `traefik-plugin-protocol-header/` directory contains a custom Traefik middleware plugin that adds the `X-Original-Protocol` header with the original HTTP version (HTTP/1.1, HTTP/2.0, HTTP/3.0). This is critical for bot detection because:
- Real browsers negotiate HTTP/2+ via TLS ALPN
- Bot HTTP libraries (Python requests, Go net/http, curl) use HTTP/1.1
- ForwardAuth always uses HTTP/1.1 internally, so without this plugin the middleware can't see the original protocol

**Deployment:** Mount the plugin directory at `/plugins-local/src/github.com/myspeedpuzzling/traefik-plugin-protocol-header` in the Traefik container and enable it in static config under `experimental.localPlugins`.

## Adding Bot Patterns

Add entries to the `BLOCKED_BOTS` array:
```javascript
{ pattern: /BotName/i, reason: 'Description' }
```

## Adding Blocked Subnets

Add entries to the `BLOCKED_CIDRS` array (uses prefix matching, no external dependencies):
```javascript
{ prefix: '43.104.33.', reason: 'Known botnet subnet' }
```

## Adding Cloud Provider CIDR Ranges

Add entries to the `CLOUD_PROVIDER_CIDRS` array (uses proper bitmask matching):
```javascript
{ network: 0x96058000, mask: 0xFFFF8000, name: 'ProviderName' }  // 150.5.128.0/17
```
Use `ipToInt()` to convert IP addresses. Source for ranges: https://github.com/ipverse/asn-ip

## Environment Variables

- `PORT` (3000) - server port
- `RATE_LIMIT` (45) - max requests per window
- `RATE_WINDOW` (60000) - window in ms
- `LOCALE_THRESHOLD` (4) - unique locales to trigger ban
- `LOCALE_MIN_HITS` (3) - min requests per locale
- `LOCALE_WINDOW` (60000) - detection window in ms
- `BAN_DURATION` (30 days) - ban duration in ms
- `CONTACT_EMAIL` - shown on block pages
- `LOG_DIR` (/var/log/bot-blocker) - log output directory
