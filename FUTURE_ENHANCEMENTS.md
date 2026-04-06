# Future Bot Detection Enhancements

Notes from analysis session 2026-04-04 through 2026-04-06.

## Fingerproxy — JA3/JA4/HTTP2 fingerprinting (next level)

If bots evolve to use HTTP/2 libraries, our current protocol-based detection won't catch them.
The next escalation is TLS fingerprinting via [Fingerproxy](https://github.com/wi1dcard/fingerproxy):

- **What it does**: Sits in front of Traefik, terminates TLS, generates JA3/JA4/HTTP2 fingerprint headers
- **Architecture**: `Client → Fingerproxy (:443) → Traefik (:80) → Backend`
- **Key signal**: `X-HTTP2-Fingerprint` empty = client used HTTP/1.1. `X-JA4-Fingerprint` identifies exact HTTP client implementation (Python requests, Go net/http, curl, real Chrome all have distinct JA4 hashes)
- **Why JA4 > JA3**: Chrome 110+ randomizes TLS extension order, breaking JA3 stability. JA4 (by FoxIO) sorts extensions before hashing, remaining stable
- **Production proven**: 40M requests/day
- **Traefik limitation**: Traefik itself declined JA3/JA4 support ([traefik/traefik#8627](https://github.com/traefik/traefik/issues/8627)) — TLS handshake data not available at plugin level. Fingerproxy placed upstream is the workaround.
- **Multi-domain challenge**: Fingerproxy takes single cert pair. For multiple domains (myspeedpuzzling.com, terlicko.cz, etc.) need either wildcard certs, multiple instances, or switch to Caddy/HAProxy which handle SNI natively
- **Cert management**: Would need traefik-certs-dumper to extract PEMs from Traefik's acme.json, or switch cert management to certbot/acme.sh

### Alternative: Huginn Proxy

[github.com/biandratti/huginn-proxy](https://github.com/biandratti/huginn-proxy) — similar concept: passive reverse proxy that fingerprints TLS (JA4), HTTP/2 (Akamai), and TCP SYN (p0f via eBPF/XDP), forwarding signatures as headers.

### Alternative: Finch

[github.com/0x4D31/finch](https://github.com/0x4D31/finch) — fingerprint-aware TLS reverse proxy that can directly block, tarpit, or reroute based on JA3/JA4/HTTP2 fingerprints using HCL rules. Not yet production-ready (v0.1.0) but architecturally the most powerful option.

## CrowdSec — community IP reputation

- [crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin) — native Traefik plugin
- Analyses Traefik access logs, detects attack patterns, pushes ban decisions
- Community blocklist provides crowd-sourced IP reputation
- Premium tier has botnet-specific blocklists
- Setup guides: [blog.lrvt.de](https://blog.lrvt.de/configuring-crowdsec-with-traefik/), [mattdyson.org](https://mattdyson.org/blog/2025/03/securing-traefik-with-crowdsec/)

## Anubis — JavaScript proof-of-work challenge

- [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis) — Go-based, integrates with Traefik via ForwardAuth
- First visit: ~1-2 second SHA-256 challenge in WebWorker, cookie stored, subsequent visits instant
- Bots using plain HTTP clients can't execute JS → auto-blocked
- Can be applied selectively to scraped pages only (puzzle/profile paths via Traefik routing)
- **Downside**: UX impact on first visit ("checking your browser"), feels corporate
- **Downside**: Blocks legitimate bots like Internet Archive unless whitelisted upstream
- Best as last resort for persistent scrapers that evolve past all other detection

## Cloud provider ASN IP lists (daily-updated)

Source: [github.com/ipverse/asn-ip](https://github.com/ipverse/asn-ip)

| Provider | ASN | Current coverage |
|----------|-----|-----------------|
| BytePlus/ByteDance | AS150436 | Covered (150.5, 163.7, 101.47) |
| Tencent Cloud | AS132203, AS45090, AS133478 | Partially covered |
| Alibaba Cloud | AS45102, AS134963 | Covered (47.x, 8.x) |
| AWS | AS16509, AS14618 | NOT covered — too many real users on AWS |
| GCP | AS15169 | NOT covered — includes Google services |
| Azure | AS8075 | NOT covered |
| DigitalOcean | AS14061 | Consider adding if seen in bot traffic |
| Vultr | AS20473 | Consider adding if seen in bot traffic |
| OVH | AS16276 | Consider adding if seen in bot traffic |
| Hetzner | AS24940 | Consider adding if seen in bot traffic |

Could automate: cron job fetches CIDR lists from ipverse nightly, bot-blocker reloads.

## Tarpit / deception (waste bot resources)

- **Nepenthes** ([forge.hackers.town](https://forge.hackers.town/hackers.town/nepenthes)) — generates infinite fake pages with internal links, trapping crawlers in recursion
- **Sarracenia** ([github.com/CTAG07/Sarracenia](https://github.com/CTAG07/Sarracenia)) — Go-based tarpit inspired by Nepenthes
- **HTTP tarpit**: Send 200 OK then deliver body at 1 byte/second — bot waits forever
- Could redirect detected bots to tarpit instead of clean 403

## Other detection signals to explore

- **Accept-Language header**: bots often omit or send generic "en-US". Could check if Traefik forwards this
- **Accept/Accept-Encoding headers**: bots often have minimal or missing accept headers
- **Session behaviour**: real users navigate (home → puzzle list → puzzle detail). Bots jump directly to deep pages
- **Response size**: bots that don't load CSS/JS/images have different response patterns
- **TLS version**: TLS 1.2 vs 1.3 (most modern browsers use 1.3, some bots use 1.2) — available via Traefik access logs but not forwarded to middleware yet

## Known botnet context

HN threads documenting the same botnet we're fighting:
- ["Nearly 90% of AI crawler traffic is from ByteDance"](https://news.ycombinator.com/item?id=42009636)
- ["How to keep Chinese crawlers from taking down my site"](https://news.ycombinator.com/item?id=42659443)
- BytePlus (AS150436) is especially aggressive — ByteDance's B2B cloud, NOT consumer-facing
- Many site operators block BytePlus/Tencent/Alibaba ASNs entirely with no real-user impact
