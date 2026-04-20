# UA Velocity Detection

Detects a single User-Agent string being shared by many distinct IPs in a short window **and** those IPs collectively exhibiting a "content scraper" behavioral signature. Blocks only new untrusted IPs using that UA.

Lives in `server.js` alongside the other in-process trackers; the plan is at `/Users/janmikes/.claude/plans/agile-twirling-parnas.md` (for historical context).

---

## Why

A Chinese residential-proxy botnet bypasses every UA-based, CIDR-based, and HTTP/1.1-vs-HTTP/2 defense by driving **real Chromium** (Puppeteer/Playwright) through distributed residential proxies. At the HTTP wire level it is indistinguishable from a real browser.

Observed 2026-04-16 19:00–20:00 CEST:
- **91 distinct Chinese IPs** in 1 hour
- **All** share the exact UA `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36`
- **89/91** load full HTML + assets (webpack chunks, fonts, service-worker.js)
- **88/91** enter directly on UUID-addressed pages (`/en/puzzle/UUID`, `/en/player-profile/UUID`)
- **0/91** visit the homepage

Since Chrome's User-Agent Reduction (Chrome 110+), every real Chrome 142 user on Win10 sends that exact UA string. We cannot block the UA globally — we must look at **aggregate behavior across many IPs sharing a UA** to distinguish a botnet fingerprint from the long tail of real users.

**Reliability is the single hard constraint.** Blocking real users is a worse outcome than letting some bots through.

---

## What

A per-request check that:

1. Keeps a rolling 10-minute record per UA: how many distinct IPs used it, how many entered via a UUID page, how many hit the homepage/a listing, and how many distinct UUID paths were hit across all those IPs.
2. Flags a UA when the record matches a scraper signature (high IP count, high UUID-entry count, high path diversity, near-zero homepage visits).
3. Blocks requests that hit the flagged UA **unless** the specific IP has shown real-user behavior (trusted IP) **or** the request is itself a recovery path (homepage, listing, login, POST).
4. Also evaluates a **stricter shadow tier** that only logs — never blocks. Gives data to safely tighten enforcement over time.

Key properties:
- **Two-tier thresholds** (Tier A enforces, Tier B shadow-logs).
- **Trusted-IP bypass** — hitting any trust-marker path in the last 24h = IP bypasses velocity blocks.
- **Soft-whitelist** for social in-app browsers (FBAN / Instagram / MicroMessenger / Line / Snapchat / Twitter for iPhone) so viral social shares never flag.
- **Block action is 429** with a redirect-to-homepage HTML page (auto-redirect after 3s) — real users recover without contact.
- **Flag persistence across window rolls, keep-alive, and container restarts** — once a UA is flagged, the flag survives the internal 10-min window reset, is kept alive for 10 min past the last block, and is saved to `flagged-uas.json` so a deploy/restart doesn't gift the botnet a fresh grace window.
- **Flag TTL** (10 min since last block activity) — dormant UAs naturally expire; sustained attacks stay flagged indefinitely.
- **Kill switch** — `UA_VELOCITY_ENFORCE=false` turns enforcement off while keeping shadow logs.

---

## How

### Decision flow per HTML request (after all cheaper block checks have passed)

```
request
  ├─ static asset?         → 200 (no velocity work)
  ├─ whitelisted bot?      → 200 (Googlebot etc.)
  ├─ permaban / blocked path / blocked bot / empty UA / CIDR / Chinese botnet / fake iOS / cloud botnet / HTTP/1.1 browser
  │                        → 403 (existing checks)
  ├─ UPDATE uaVelocityTracker[ua]:
  │     add ipKey; if NEW ip → increment uuidEntries or homepageVisits
  │     if UUID path → add to uniqueUuidPaths
  │     re-evaluate Tier A → if met, flagged=true, flaggedAt=now, log [UA_VELOCITY_FLAG]
  │     re-evaluate Tier B → if met (and not yet shadow-logged), log [UA_VELOCITY_SHADOW]
  ├─ if trust-marker path/method → markIpTrusted(ipKey)
  ├─ shouldBlockByUaVelocity?
  │     flagged AND fresh AND IP untrusted AND path not trust-marker
  │     → 429 with recovery HTML (X-Blocked-Reason: ua_velocity)
  └─ continue to Chrome span / locale / page scrape / rate limit / 200
```

### Data structures (`server.js`)

```js
const uaVelocityTracker = new Map();
// UA → { ips: Set<ipKey>, uuidEntries, homepageVisits,
//        uniqueUuidPaths: Set<string>, windowStart, flagged, flaggedAt, shadowLogged }

const trustedIpTracker = new Map();
// ipKey → { lastGoodAction }   (24h TTL)
```

### Trust markers

Evidence the visitor is a real user. Any of:
- root / locale root (`/`, `/en`, `/cs`, …)
- homepage (`/en/home`, …)
- listing page (`/en/puzzles`, `/en/players`, `/en/brands`, `/en/blog`, `/en/competitions`, `/en/news`, `/en/events`, `/en/sale`, `/en/manufacturers`, `/en/shops`, `/en/rankings`, `/en/leaderboard`, `/en/statistics`, `/en/announcement`, `/en/calendar`) — same for each locale
- login / register / account / settings / profile-edit / logout / password
- `/puzzle-stopky` landing (CS root-relative)
- any POST / PUT / DELETE request (bots rarely submit forms)

### UUID-entry detection

Regex: `/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i` (RFC 4122).

### IP key

IPv4 → full address. IPv6 → collapse to `/64` prefix (so one subscriber's IPv6 rotation counts as one IP).

### In-app browser exemption

Regex: `/FBAN|FBAV|Instagram|MicroMessenger|\bLine\/|Snapchat|Twitter for iPhone/i`.
UAs matching this bypass velocity tracking entirely — legitimate viral social shares never flag.

### Flag-condition math (integer — no float comparisons)

Tier A (enforce):
```
ips.size                  >= ENFORCE_MIN_IPS              (default 40)
uuidEntries               >= ENFORCE_MIN_UUID_ENTRIES     (default 30)
uniqueUuidPaths.size      >= ENFORCE_MIN_UNIQUE_PATHS     (default 20)
homepageVisits * 100      <  ips.size * ENFORCE_MAX_HOMEPAGE_PCT    (default 10 → <10%)
uniqueUuidPaths.size*100  >= ips.size * ENFORCE_MIN_PATH_DIVERSITY  (default 50 → ≥50%)
```

Tier B (shadow): same shape with stricter defaults (25 / 20 / 15 / 5% / 40%).

### Block decision

A request is blocked if ALL:
1. UA flagged AND `now - flaggedAt < UA_VELOCITY_FLAG_TTL` (default 10 min)
2. Current path is NOT a trust marker
3. `trustedIpTracker[ipKey]` has no `lastGoodAction` in the last 24h
4. `UA_VELOCITY_ENFORCE === true`

On each block the IP+UA pair accumulates a **strike**. On the **3rd strike in 24h** (default, via `UA_VELOCITY_STRIKES_FOR_BAN`), the IP is **permanently banned** via the existing `banIP()` infrastructure (30-day ban persisted to `banned-ips.json`).

**Response codes:**
- Strikes 1–2: `HTTP 429`, `Retry-After: 300`, `X-Blocked-Reason: ua_velocity`, `X-Robots-Tag: noindex, nofollow`. HTML has a **manual** "Go to homepage" button — no auto-redirect (see note below).
- Strike N (default 3): `HTTP 403`, `X-Blocked-Reason: ua_velocity_ban`, generic bot-blocked HTML with permaban reason.

**Why no auto-redirect:** early testing showed Puppeteer-driven bots were following `<meta http-equiv="refresh">` to the homepage, which returned 200 + GA JS, so they still counted as "visitors" in Google Analytics. The manual button lets real users recover (one click) while bots stay on the 429 page and never fire GA.

**Why strike is IP+UA keyed, ban is IP-only:** a real user sharing a CGNAT IP with a separate UA will never strike because their UA doesn't match the flagged bot UA. The ban itself piggybacks the existing IP-keyed `banIP()` for simplicity; by the time an IP+UA pair reaches 3 strikes, the IP is almost certainly a dedicated bot (residential proxy endpoint).

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `UA_VELOCITY_ENFORCE` | `true` | Global kill switch. Set `false` for dry-run (logs only). |
| `UA_VELOCITY_WINDOW` | `600000` (10 min) | Rolling window for UA → IP aggregation. |
| `UA_VELOCITY_FLAG_TTL` | `600000` (10 min) | Flag expires after this long without re-fire. |
| `UA_VELOCITY_ENFORCE_MIN_IPS` | `40` | Tier A: min distinct IPs to flag. |
| `UA_VELOCITY_ENFORCE_MIN_UUID_ENTRIES` | `30` | Tier A: min IPs whose first-seen path was UUID. |
| `UA_VELOCITY_ENFORCE_MIN_UNIQUE_PATHS` | `20` | Tier A: min distinct UUID paths hit. |
| `UA_VELOCITY_ENFORCE_MAX_HOMEPAGE_PCT` | `10` | Tier A: homepage visits must be `< X%` of ips. |
| `UA_VELOCITY_ENFORCE_MIN_PATH_DIVERSITY` | `50` | Tier A: `uniqueUuidPaths / ips` must be `>= X%`. |
| `UA_VELOCITY_SHADOW_MIN_IPS` | `25` | Tier B shadow: log-only stricter thresholds. |
| `UA_VELOCITY_SHADOW_MIN_UUID_ENTRIES` | `20` | Tier B. |
| `UA_VELOCITY_SHADOW_MIN_UNIQUE_PATHS` | `15` | Tier B. |
| `UA_VELOCITY_SHADOW_MAX_HOMEPAGE_PCT` | `5` | Tier B. |
| `UA_VELOCITY_SHADOW_MIN_PATH_DIVERSITY` | `40` | Tier B. |
| `UA_VELOCITY_STRIKES_FOR_BAN` | `3` | Strikes by same IP+UA pair in window → permaban. |
| `UA_VELOCITY_STRIKE_WINDOW` | `86400000` (24h) | Rolling window for counting strikes. |

---

## Reliability — how each realistic risk is defused

| Risk | Defense |
|---|---|
| Viral link — many real users hit ONE UUID | `uniqueUuidPaths.size >= 20` + `path diversity >= 50%` — viral traffic converges on 1 URL and fails both gates |
| Newsletter blast — one link | Same as above |
| Puzzle competition / livestream | Same as above, plus in-app browser whitelist catches social shares |
| Chrome auto-update rollout | Real morning traffic hits homepage heavily; `homepage > 10%` disqualifies |
| First-time real Chinese visitor arriving via shared UUID link while UA is flagged | 429 page shows "visit homepage" recovery link; the homepage hit marks the IP trusted; next UUID request passes |
| Grace window leaking IPs every 10 min (window reset wiping flag) | Fixed: `updateUaVelocity` carries `flagged`/`flaggedAt` across window rolls while within FLAG_TTL |
| Flag expiring mid-attack while botnet still active | Fixed: `shouldBlockByUaVelocity` keep-alives `flaggedAt = now` on every block, so flag lives as long as blocks keep firing |
| Deploy / container restart gifting fresh grace windows | Fixed: flagged UAs persisted to `flagged-uas.json` (save on flag event, save every 5 min, save on SIGTERM); `loadFlaggedUAs()` at startup restores flags still within FLAG_TTL |
| Evasion by adding decoy homepage visits | Absolute floor `uuidEntries >= 30` still fires |
| Evasion by rotating UAs | Each rotated UA must independently reach the thresholds — much more expensive botnet |
| Mobile CGNAT = 1 user looks like many IPs | Real rotation produces ~5–10 IPs, below threshold |
| Referer spoofing | Not used — we rely on path/behavior signals, not headers |
| Long-lived false-positive flag | 10-min inactivity TTL — real traffic recovers within minutes |
| Kill switch | `UA_VELOCITY_ENFORCE=false` + container restart |

---

## Runbook — reading the logs

Log lines emitted to `blocked-YYYY-MM-DD.log` and stdout:

- `[UA_VELOCITY_FLAG] ips=N uuidEntries=X uniquePaths=Y homepage=H% uuid=U% diversity=D% UA=…`
  - Emitted **once** when Tier A crosses threshold.
  - Verify it matches a known botnet UA by cross-referencing Traefik access logs.

- `[UA_VELOCITY_SHADOW] …`
  - Emitted **once per window** when stricter Tier B crosses. No block. Pure diagnostic signal.

- `[UA_VELOCITY] <ip> - Strike N/3: UA velocity: same UA from many IPs with scraper signature - <ua>`
  - Per-request 429 block. Includes strike count for the IP+UA pair.
- `[UA_VELOCITY_BAN] <ip> - Permaban on 3 UA velocity strikes - <ua>`
  - Emitted once when an IP+UA hits the strike threshold. The IP is then added to `banned-ips.json` and subsequent requests get caught by the upstream `permaban` check.

- `[UA_VELOCITY_WOULD_BLOCK] <ip> <path> UA=<ua>`
  - Only when `UA_VELOCITY_ENFORCE=false` (dry-run mode).

### Investigating a suspected false positive

1. Grep the daily log for the complaining user's IP: `rg <ip> /var/log/bot-blocker/blocked-*.log`.
2. If an entry is `type=ua_velocity`, check the accompanying UA. Find the `[UA_VELOCITY_FLAG]` line from the same window; inspect the numbers.
3. Pull Traefik access logs for that UA in the window:
   `docker logs --since=1h traefik-reverse-proxy-1 | grep <UA fragment>`.
4. Count distinct IPs and their entry paths. If the spread looks like a legitimate viral/event moment, either (a) add the source UA pattern to `IN_APP_BROWSER_RE`, (b) loosen thresholds, or (c) add the path pattern to `TRUST_MARKER_PATHS`.
5. Flip kill switch while investigating: set `UA_VELOCITY_ENFORCE=false` in compose env and `docker compose up -d bot-blocker`.

### Investigating a suspected miss

1. Observe Traefik logs for the bot UA: still loading 200s?
2. Check `[UA_VELOCITY_FLAG]` log — did the UA flag at all?
3. If not, compare actual aggregate (count IPs, uuidEntries, uniquePaths) to Tier A thresholds. If bot is just below, **check Tier B shadow logs** for the stricter signal — that's your data to safely tighten enforcement.

---

## Next steps & when

- **Week 1 post-deploy** — daily: scan `[UA_VELOCITY_FLAG]` and `[UA_VELOCITY]` against Traefik access logs. Goal: confirm only bot UAs are flagged, zero real-user impact.
- **Week 1–2** — collect `[UA_VELOCITY_SHADOW]` events. If every shadow-flagged UA is also confirmed bot by manual inspection, tighten Tier A defaults toward Tier B values (e.g. drop `MIN_IPS` from 40 → 30) and redeploy.
- **Week 2–4** — if any user complains or a trusted-IP log analysis shows collateral damage, loosen thresholds OR extend `TRUST_MARKER_PATHS` / `IN_APP_BROWSER_RE`. Record the scenario under "Known FP cases" below.
- **Month 2+** — if the botnet adapts (rotates UAs, adds homepage decoys), revisit. Candidate follow-ups (see `FUTURE_ENHANCEMENTS.md`):
  - ASN-based clustering (IP → ASN lookup via an embedded dataset) — catches botnets that rotate UAs to stay under per-UA thresholds.
  - Forward `X-Forwarded-Referer` via the Traefik protocol-header plugin; treat referer starting with `https://myspeedpuzzling.com/` as a +1 trust signal (never a primary gate — referer is spoofable).
  - JS challenge for UA-flagged + UUID-entry requests — cost-raises Puppeteer scrapers.
  - Consider Cloudflare Bot Management / JA4 if rule-based detection plateaus.
- **Sunset** — if 90 days pass with zero `[UA_VELOCITY_*]` events, feature has done its job. Keep the code in place; consider loosening thresholds further to reduce per-request work.

---

## Known FP cases

_None yet. Append dated entries here whenever a real-user complaint or trusted-IP analysis surfaces collateral damage._
