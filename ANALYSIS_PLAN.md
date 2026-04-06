# Bot Traffic Analysis Plan

Run this analysis after a few hours of the new detection running.

## Context

On 2026-04-04 we identified a massive distributed scraping botnet targeting myspeedpuzzling.com.
We deployed three new detection mechanisms:

1. **Chrome version span detection** — blocks IPs sending Win10+Chrome UAs with version span >= 10 in 10 min
2. **Expanded 43.x botnet** — blocks any 43.x + Win10 + Chrome (was Chrome 100-139 only)
3. **Cloud botnet detection** — blocks HTTP/1.1 + Win10 Chrome + cloud provider IPs (BytePlus, Alibaba, Tencent)
   via X-Original-Protocol header from custom Traefik plugin

Rate limiting and page scraping detection remain keyed by IP+UA (competition WiFi safety).

## Step 1: Check what the new detections caught

```bash
ssh root@spare.srv.thedevs.cz 'python3 << PYEOF
import json, collections
from datetime import datetime, timedelta, timezone

entries = []
with open("/deployment/traefik/bot-blocker-logs/blocked-$(date +%Y-%m-%d).log") as f:
    for line in f:
        try:
            entries.append(json.loads(line.strip()))
        except:
            pass

cutoff = datetime.now(timezone.utc) - timedelta(hours=4)
recent = [e for e in entries if datetime.fromisoformat(e["timestamp"].replace("Z","+00:00")) >= cutoff]

print("Blocked in last 4 hours: %d" % len(recent))
types = collections.Counter(e["type"] for e in recent)
for k, v in types.most_common():
    print("  %s: %d" % (k, v))
print()
reasons = collections.Counter(e["reason"] for e in recent)
print("By reason:")
for k, v in reasons.most_common(15):
    print("  %s: %d" % (k, v))
PYEOF'
```

## Step 2: Analyse Traefik access logs for suspicious traffic still getting through

Save last 5000 entries to a file and analyse (avoids streaming huge docker logs):

```bash
ssh root@spare.srv.thedevs.cz 'docker logs traefik-reverse-proxy-1 --tail 5000 > /tmp/traefik-sample.log 2>&1 && echo "saved"'
```

Then run the analysis:

```bash
ssh root@spare.srv.thedevs.cz 'python3 << PYEOF
import json, collections, re

ua_allowed = collections.Counter()
ip_allowed = collections.Counter()
protocol_allowed = collections.Counter()
suspicious = []
total_main = 0

with open("/tmp/traefik-sample.log") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue

        host = entry.get("RequestHost", "")
        status = entry.get("DownstreamStatus", 0)
        if "myspeedpuzzling" not in host or "img." in host:
            continue
        if status != 200:
            continue

        total_main += 1
        ua = entry.get("request_User-Agent", "")
        ip = entry.get("ClientHost", "")
        path = entry.get("RequestPath", "")
        protocol = entry.get("RequestProtocol", "")

        protocol_allowed[protocol] += 1

        # Skip known good: static assets, whitelisted bots
        if "/build/" in path or "/img/" in path or "/css/" in path or ".svg" in path:
            continue
        if any(b in ua for b in ["Googlebot","bingbot","Baiduspider","Google-Read-Aloud","SentryUptime"]):
            continue

        ip_allowed[ip] += 1
        ua_allowed[ua[:150]] += 1

        # Flag suspicious patterns
        is_suspicious = False
        if protocol == "HTTP/1.1" and "Windows NT 10.0" in ua and "Chrome/" in ua:
            is_suspicious = True
        elif protocol == "HTTP/1.1" and not ua:
            is_suspicious = True
        elif "Chrome/" in ua:
            m = re.search(r"Chrome/(\d+)", ua)
            if m and int(m.group(1)) < 100:
                is_suspicious = True

        if is_suspicious:
            suspicious.append("%s | %s | %s | %s" % (ip, protocol, ua[:80], path[:60]))

print("Total myspeedpuzzling 200 responses: %d" % total_main)
print()
print("=== PROTOCOL DISTRIBUTION ===")
for p, c in protocol_allowed.most_common():
    print("  %s: %d" % (p, c))
print()
print("=== TOP 20 IPs (non-static, non-bot) ===")
for ip, c in ip_allowed.most_common(20):
    print("  %s: %d" % (ip, c))
print()
print("=== TOP 20 USER AGENTS ===")
for ua, c in ua_allowed.most_common(20):
    print("  [%d] %s" % (c, ua))
print()
print("=== SUSPICIOUS REQUESTS STILL GETTING THROUGH (%d) ===" % len(suspicious))
for s in suspicious[:30]:
    print("  %s" % s)
PYEOF'
```

## Step 3: Deep suspicious traffic analysis

Look for patterns beyond the known botnet fingerprint — other bot types, unusual behaviour:

```bash
ssh root@spare.srv.thedevs.cz 'python3 << PYEOF
import json, re, collections

# Categorize ALL allowed traffic by behavioural fingerprint
categories = {
    "http11_win_chrome": [],       # Known botnet pattern
    "http11_other_browser": [],    # HTTP/1.1 but not Chrome on Windows
    "http11_no_ua": [],            # HTTP/1.1 with empty/short UA
    "http11_linux_headless": [],   # Possible headless browsers
    "h2_single_request_ip": [],    # HTTP/2 IPs with very few requests (distributed?)
    "rapid_page_access": [],       # IPs accessing many pages quickly
    "no_referer_deep_pages": [],   # Accessing deep pages without referer
    "old_chrome": [],              # Very old Chrome versions (any protocol)
    "curl_wget_python": [],        # Known HTTP client libraries
}

ip_requests = collections.Counter()
ip_paths = collections.defaultdict(list)
ip_referers = collections.defaultdict(set)
ip_uas = collections.defaultdict(set)
ip_protocols = collections.defaultdict(set)

with open("/tmp/traefik-sample.log") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        host = entry.get("RequestHost", "")
        status = entry.get("DownstreamStatus", 0)
        if "myspeedpuzzling" not in host or "img." in host or status != 200:
            continue
        ua = entry.get("request_User-Agent", "")
        ip = entry.get("ClientHost", "")
        path = entry.get("RequestPath", "")
        protocol = entry.get("RequestProtocol", "")
        referer = entry.get("request_Referer", "")

        # Skip static
        if "/build/" in path or "/css/" in path or "/fonts/" in path:
            continue
        if any(b in ua for b in ["Googlebot","bingbot","Baiduspider","Google-Read-Aloud","SentryUptime","Slackbot","Twitterbot","facebookexternalhit","WhatsApp","Discordbot","LinkedInBot","TelegramBot"]):
            continue

        ip_requests[ip] += 1
        ip_paths[ip].append(path[:80])
        ip_uas[ip].add(ua[:150])
        ip_protocols[ip].add(protocol)
        if referer:
            ip_referers[ip].add(referer[:80])

        # Categorize
        if not ua or len(ua) < 20:
            categories["http11_no_ua"].append("%s | %s | %s" % (ip, ua[:40], path[:60]))
        elif any(lib in ua.lower() for lib in ["curl","wget","python-requests","httpie","go-http","java/","axios","node-fetch","scrapy","httpclient"]):
            categories["curl_wget_python"].append("%s | %s" % (ip, ua[:80]))
        elif protocol == "HTTP/1.1" and "Windows NT 10.0" in ua and "Chrome/" in ua:
            categories["http11_win_chrome"].append(ip)
        elif protocol == "HTTP/1.1" and ("headless" in ua.lower() or "phantomjs" in ua.lower() or "selenium" in ua.lower()):
            categories["http11_linux_headless"].append("%s | %s" % (ip, ua[:80]))
        elif protocol == "HTTP/1.1":
            categories["http11_other_browser"].append("%s | %s | %s" % (ip, ua[:80], path[:50]))

        # Old Chrome check (any protocol)
        if "Chrome/" in ua:
            m = re.search(r"Chrome/(\d+)", ua)
            if m and int(m.group(1)) < 110:
                categories["old_chrome"].append("%s | %s | Chrome/%s | %s" % (ip, protocol, m.group(1), path[:50]))

        # Deep page without referer
        if not referer and path.count("/") >= 3 and "/puzzle/" not in path[:10] and path != "/":
            categories["no_referer_deep_pages"].append("%s | %s | %s" % (ip, protocol, path[:60]))

print("=== TRAFFIC CATEGORIZATION ===")
print()
for cat, items in categories.items():
    if items:
        unique_ips = len(set(i.split(" | ")[0] if " | " in i else i for i in items))
        print("%s: %d requests from %d IPs" % (cat, len(items), unique_ips))
        # Show sample
        for item in items[:5]:
            print("  %s" % item)
        if len(items) > 5:
            print("  ... and %d more" % (len(items) - 5))
        print()

# IPs with many unique pages (potential scrapers even on HTTP/2)
print("=== IPs WITH MOST UNIQUE PAGES (potential scrapers) ===")
for ip, count in ip_requests.most_common(20):
    unique_pages = len(set(ip_paths[ip]))
    protocols = ip_protocols[ip]
    uas = ip_uas[ip]
    has_referer = len(ip_referers[ip]) > 0
    # Flag if many unique pages + no referer + single UA
    flag = ""
    if unique_pages > 10 and not has_referer:
        flag = " <<< NO REFERER"
    if unique_pages > 10 and len(uas) > 2:
        flag += " <<< MULTI-UA"
    print("  %s: %d reqs, %d unique pages, %s, %d UAs, referer: %s%s" % (
        ip, count, unique_pages, "/".join(protocols), len(uas),
        "yes" if has_referer else "NO", flag))
PYEOF'
```

## Step 4: Check if HTTP/1.1 + Windows Chrome from non-cloud IPs is still a problem

```bash
ssh root@spare.srv.thedevs.cz 'python3 << PYEOF
import json, re, collections

http11_win_chrome = collections.Counter()
http11_win_chrome_ua = collections.defaultdict(set)

with open("/tmp/traefik-sample.log") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        host = entry.get("RequestHost", "")
        status = entry.get("DownstreamStatus", 0)
        if "myspeedpuzzling" not in host or "img." in host or status != 200:
            continue
        ua = entry.get("request_User-Agent", "")
        protocol = entry.get("RequestProtocol", "")
        ip = entry.get("ClientHost", "")
        path = entry.get("RequestPath", "")
        if "/build/" in path or "/css/" in path or ".svg" in path:
            continue
        if protocol == "HTTP/1.1" and "Windows NT 10.0" in ua and "Chrome/" in ua:
            http11_win_chrome[ip] += 1
            http11_win_chrome_ua[ip].add(ua[:120])

if http11_win_chrome:
    print("HTTP/1.1 + Win Chrome still getting through from non-cloud IPs:")
    for ip, c in http11_win_chrome.most_common(20):
        uas = http11_win_chrome_ua[ip]
        print("  %s: %d reqs, %d UAs" % (ip, c, len(uas)))
        for ua in list(uas)[:2]:
            print("    %s" % ua)
    print()
    print("ACTION: If these are all bots, consider blocking HTTP/1.1 + Windows Chrome")
    print("globally (not just cloud IPs). Real Chrome on Windows uses HTTP/2+.")
else:
    print("No HTTP/1.1 + Windows Chrome traffic getting through. Cloud botnet fully blocked!")
PYEOF'
```

## Step 5: Compare before vs after

```bash
ssh root@spare.srv.thedevs.cz 'echo "=== Before (Apr 3) ===" && head -3 /deployment/traefik/bot-blocker-logs/summary-2026-04-03.txt && echo && echo "=== After (today) ===" && cat /deployment/traefik/bot-blocker-logs/blocked-$(date +%Y-%m-%d).log | wc -l && echo "blocked requests today"'
```

## What to look for

1. **cloud_botnet blocks appearing** — Traefik plugin working, cloud bots being caught
2. **HTTP/1.1 + Windows Chrome from non-cloud IPs** — may need to expand blocking beyond cloud IPs to ALL HTTP/1.1 + Windows Chrome (real Chrome always uses HTTP/2+)
3. **HTTP/1.1 + other browsers** — Firefox/Safari on HTTP/1.1 could also be bots, but need careful analysis
4. **IPs with many unique pages but no referer** — classic scraper pattern even on HTTP/2
5. **Multi-UA IPs** — IPs using multiple different user agents (rotation)
6. **Old Chrome versions (< 110)** — even on HTTP/2, Chrome 103-109 in 2026 is extremely suspicious
7. **Known HTTP libraries** — curl, Python requests, Go net/http getting through
8. **New bot patterns** — bots may adapt (switch to HTTP/2 libraries, use real browser fingerprints)
9. **False positives** — check if any real user traffic is being blocked

## Decision framework for new rules

Before adding a new blocking rule, verify:
- [ ] Would this rule block any real user at a puzzle competition (1000 people, shared WiFi)?
- [ ] Is the signal strong enough on its own, or does it need compound signals?
- [ ] Can we test it by checking historical logs first?

---

See `FUTURE_ENHANCEMENTS.md` for JA3/JA4 fingerprinting, CrowdSec, Anubis PoW, tarpit techniques, and other enhancement notes.
