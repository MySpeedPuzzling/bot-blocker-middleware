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
2. Blocked path check → immediate 403 for WordPress exploits, `.env`, `.git` access
3. Bot detection → 403 for known bad user agents (SEO bots, AI crawlers, impossible browser combos)
4. Rate limiting → 429 if IP exceeds `RATE_LIMIT` requests per `RATE_WINDOW`
5. Allow → 200 OK

**Key data structures in `server.js`:**
- `STATIC_ASSET_PATTERNS` - regex array for paths excluded from rate limiting
- `BLOCKED_PATHS` - objects with `pattern` and `reason` for malicious path detection
- `BLOCKED_BOTS` - objects with `pattern` and `reason` for user agent blocking
- `requests` Map - in-memory rate limit tracking per IP

**Traefik headers used:**
- `X-Forwarded-For` - client IP
- `X-Forwarded-User-Agent` - original user agent
- `X-Forwarded-URI` - original request path

## Adding Bot Patterns

Add entries to the `BLOCKED_BOTS` array:
```javascript
{ pattern: /BotName/i, reason: 'Description' }
```

## Environment Variables

- `PORT` (3000) - server port
- `RATE_LIMIT` (30) - max requests per window
- `RATE_WINDOW` (60000) - window in ms
- `CONTACT_EMAIL` - shown on block pages
- `LOG_DIR` (/var/log/bot-blocker) - log output directory
