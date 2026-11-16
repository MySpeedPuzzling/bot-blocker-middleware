#!/usr/bin/env node
// =============================================================================
// build-geodb.mjs — compiles the free DB-IP lite databases into the compact
// binary range files server.js binary-searches at runtime (see the GEOIP
// section there for the record formats — keep both sides in sync).
//
// Runs at IMAGE BUILD time (Dockerfile geodb stage); the monthly scheduled CI
// rebuild keeps the data fresh. DB-IP lite is CC BY 4.0 — the attribution
// lives in README.md ("IP geolocation by DB-IP").
//
// Usage:  node scripts/build-geodb.mjs <outDir>
//   env GEODB_SRC_DIR=<dir>  read dbip-country-lite.csv.gz /
//                            dbip-asn-lite.csv.gz from a local dir instead of
//                            downloading (tests, offline builds)
//   env SKIP_CRAWLER_ASN=1   skip the RIPEstat crawler-ASN fetch (offline builds)
//
// FAIL-OPEN CONTRACT: if no database can be fetched (network down, DB-IP
// gone), this script writes an EMPTY meta.json and exits 0 — the image still
// builds and server.js degrades gracefully (geo/ASN signals score 0). A red
// CI over a third-party CDN hiccup would be worse than a month-stale GeoDB.
// =============================================================================

import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';

const OUT_DIR = process.argv[2];
if (!OUT_DIR) {
  console.error('usage: build-geodb.mjs <outDir>');
  process.exit(1);
}
mkdirSync(OUT_DIR, { recursive: true });

// -----------------------------------------------------------------------------
// Google published crawler/fetcher IP lists → google-ranges.json
// -----------------------------------------------------------------------------
// Baked copy of the four lists server.js verifies Google fetchers against (it
// also refreshes them at runtime; this copy covers the first minutes after
// start and any period Google's site is unreachable). Written FIRST and
// independently, so the DB-IP fail-open exit below never skips it. A list that
// cannot be fetched is simply absent; an entirely failed fetch writes no file.
const GOOGLE_RANGE_LISTS = {
  'common-crawlers': 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
  'special-crawlers': 'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
  'user-triggered-fetchers': 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
  'user-triggered-fetchers-google': 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
};
if (process.env.SKIP_GOOGLE_RANGES) {
  console.log('[geodb] SKIP_GOOGLE_RANGES set — no google-ranges.json');
} else {
  const lists = {};
  for (const [name, url] of Object.entries(GOOGLE_RANGE_LISTS)) {
    try {
      const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(20000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      const cidrs = (body.prefixes || []).map(p => p.ipv4Prefix || p.ipv6Prefix).filter(Boolean);
      if (cidrs.length === 0) throw new Error('no prefixes');
      lists[name] = cidrs;
      console.log(`[geodb] Google ${name}: ${cidrs.length} prefixes`);
    } catch (err) {
      console.error(`[geodb] WARNING: Google ${name} failed (${err.message}) — runtime refresh must supply it`);
    }
  }
  if (Object.keys(lists).length > 0) {
    writeFileSync(join(OUT_DIR, 'google-ranges.json'),
      JSON.stringify({ built: new Date().toISOString(), lists }));
  }
}

// Org-name keywords that classify an ASN as hosting/datacenter. Substring
// match on the lowercased org. Deliberately broad — the signal only ADDS
// risk score toward a solvable challenge, never a hard block, so a stray
// ISP with "host" in its name costs a real user one invisible Turnstile.
const DC_KEYWORDS = [
  // hyperscalers + chinese clouds (the observed botnets)
  'amazon', 'aws', 'google llc', 'google cloud', 'microsoft', 'azure', 'oracle',
  'alibaba', 'aliyun', 'tencent', 'huawei', 'baidu', 'bytedance', 'byteplus',
  'kingsoft', 'ucloud', 'qiniu',
  // big hosting
  'ovh', 'hetzner', 'digitalocean', 'linode', 'akamai', 'vultr', 'choopa',
  // ('1&1' was here until 2026-11-16: it matched "1&1 Versatel GmbH", a German
  // residential/business ISP — real puzzlers. IONOS hosting is still caught
  // by 'ionos'.)
  'contabo', 'leaseweb', 'ionos', 'scaleway', 'online s.a.s', 'upcloud',
  'kamatera', 'hostinger', 'namecheap', 'godaddy', 'rackspace', 'softlayer',
  'ibm cloud', 'hivelocity', 'psychz', 'quadranet', 'colocrossing', 'serverius',
  'worldstream', 'greencloud', 'zenlayer', 'gcore', 'g-core', 'cdn77',
  'datacamp', 'm247', 'hostroyale', 'bucklog', 'stark industries', 'aeza',
  'packethub', 'clouvider', 'velia', 'fdcservers', 'terrahost', 'netcup',
  'liteserver', 'novogara', 'heficed', 'kaopu', 'lightnode', 'pq hosting',
  'melbicom', 'alexhost', '3xk tech', 'gigabit', 'estnoc',
  // generic
  'hosting', 'host ', ' host', 'server', 'cloud', 'vps', 'dedicated',
  'datacenter', 'data center', 'data-center', 'colocation', 'colo ',
  'proxy', 'vpn', 'cdn',
];

function isDatacenterOrg(org) {
  const lower = org.toLowerCase();
  return DC_KEYWORDS.some(k => lower.includes(k));
}

// Hosting / ISP-proxy networks classified by ASN NUMBER, because their org
// names carry no keyword. Each entry is evidence-backed (lily.srv D96): during
// the 2026-11-13..15 wave these exits solved the Turnstile challenge at rates
// no human population produces, one solve per IP, identical Linux Chrome.
//   AS398781 OCULUS NETWORKS INC — ISP-proxy seller routed via Hurricane
//            Electric (leased blocks incl. 40.223/16, 172.252/16); 2 979
//            solver IPs in 3 days, ~50-70 % solve rate.
//   AS62874  Web2Objects LLC, AS35916 MULTACOM CORPORATION — hosting/colo.
//   AS209709 UAB code200 — proxy provider.
const DC_ASNS = new Map([
  ['398781', 'OCULUS NETWORKS INC'],
  ['62874', 'Web2Objects LLC'],
  ['35916', 'MULTACOM CORPORATION'],
  ['209709', 'UAB code200'],
]);

// ASNs that are REAL consumer ISPs but also announce leased foreign blocks
// that proxy sellers resell as "residential". Only the listed first octets
// are classified; the ISP's own ranges stay untouched. AS22773 = Cox
// Communications: genuine Cox lives in 24/68/70/72/98/174/184/…; the
// AFRINIC /8s (and its 45.x blocks) announced under Cox produced 638 solver
// IPs in 3 days, real Cox ranges ~20 (humans).
const DC_ASN_OCTETS = new Map([
  ['22773', { octets: new Set([41, 45, 102, 105, 154, 156, 196, 197]),
    label: 'Cox-labelled leased block (ISP proxy)' }],
]);

// Datacenter label for an ASN range, or null for residential/unknown.
function datacenterLabel(asn, org, start) {
  if (DC_ASNS.has(asn)) return DC_ASNS.get(asn);
  const byOctet = DC_ASN_OCTETS.get(asn);
  if (byOctet) {
    return byOctet.octets.has(start >>> 24) ? byOctet.label : null;
  }
  return org && isDatacenterOrg(org) ? org : null;
}

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const n = ((parseInt(parts[0], 10) << 24) | (parseInt(parts[1], 10) << 16)
    | (parseInt(parts[2], 10) << 8) | parseInt(parts[3], 10)) >>> 0;
  return Number.isFinite(n) ? n : null;
}

// Minimal CSV line parser (org names contain quoted commas).
function csvFields(line) {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else { inQuotes = false; }
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      fields.push(cur); cur = '';
    } else {
      cur += ch;
    }
  }
  fields.push(cur);
  return fields;
}

async function fetchDb(name) {
  const srcDir = process.env.GEODB_SRC_DIR;
  if (srcDir) {
    const file = join(srcDir, `${name}.csv.gz`);
    if (existsSync(file)) {
      console.log(`[geodb] using local ${file}`);
      return gunzipSync(readFileSync(file)).toString('utf8');
    }
    console.error(`[geodb] GEODB_SRC_DIR set but ${file} missing`);
    return null;
  }

  // DB-IP publishes per-month files; on month rollover the current month can
  // 404 for a few days — walk back up to 3 months.
  const now = new Date();
  for (let back = 0; back < 3; back++) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
    const stamp = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
    const url = `https://download.db-ip.com/free/${name}-${stamp}.csv.gz`;
    try {
      const res = await fetch(url, { redirect: 'follow' });
      if (!res.ok) {
        console.log(`[geodb] ${url} -> HTTP ${res.status}`);
        continue;
      }
      const buf = Buffer.from(await res.arrayBuffer());
      console.log(`[geodb] downloaded ${url} (${(buf.length / 1048576).toFixed(1)} MiB)`);
      return gunzipSync(buf).toString('utf8');
    } catch (err) {
      console.log(`[geodb] ${url} failed: ${err.message}`);
    }
  }
  return null;
}

function writeEmpty(reason) {
  writeFileSync(join(OUT_DIR, 'meta.json'), JSON.stringify({
    built: new Date().toISOString(), empty: true, reason, countries: [], dcOrgs: [],
    crawlerAsns: [],
  }));
  writeFileSync(join(OUT_DIR, 'crawler-asn.bin'), Buffer.alloc(0));
  console.error(`[geodb] WARNING: shipping EMPTY geodb (${reason}) — geo/ASN risk signals will be disabled`);
  process.exit(0);
}

// -----------------------------------------------------------------------------
// Verified-crawler ASNs
// -----------------------------------------------------------------------------
// Some crawler operators do NOT publish reverse DNS for their fetchers, so the
// forward-confirmed rDNS check server.js uses for Googlebot/Bingbot cannot work
// for them. Meta is the case that bit us: 57.141.0.0-57.149.255.255 is FB-BLOCK
// (Meta Platforms Ireland, RIPE) but the addresses have NO PTR record at all, so
// every facebookexternalhit / meta-externalagent / meta-webindexer request was
// classified `fake` and fell through to risk scoring — which challenged it. That
// silently broke Facebook/Messenger/WhatsApp/Instagram link previews (1,508
// facebookexternalhit hits blocked in 48h, 2026-08-03..05). Meta documents
// verification by their published IP ranges / AS32934 — not by rDNS.
//
// So: compile the ASN's currently-announced IPv4 prefixes into a range file and
// let server.js verify membership. Same fail-open philosophy as everything else
// here — if RIPEstat is unreachable the file ships EMPTY and server.js honours
// the UA-only whitelist (still rate-capped), because a broken link preview is
// worse than briefly trusting a spoofable UA at 30 req/min.
const CRAWLER_ASNS = [
  { asn: 32934, name: 'Meta Platforms' },
];

async function fetchAsnPrefixes(asn) {
  const url = `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`;
  try {
    const res = await fetch(url, { redirect: 'follow' });
    if (!res.ok) {
      console.log(`[geodb] AS${asn} -> HTTP ${res.status}`);
      return null;
    }
    const body = await res.json();
    if (body.status !== 'ok' || !body.data || !Array.isArray(body.data.prefixes)) {
      console.log(`[geodb] AS${asn} -> unexpected payload`);
      return null;
    }
    return body.data.prefixes.map(p => p.prefix).filter(p => p && !p.includes(':'));
  } catch (err) {
    console.log(`[geodb] AS${asn} failed: ${err.message}`);
    return null;
  }
}

// "1.2.3.0/24" -> [firstInt, lastInt]; null when malformed or a silly prefix
// length (a /0..7 from a bad feed would whitelist a huge slice of the internet).
function cidrToRange(cidr) {
  const [addr, bitsRaw] = cidr.split('/');
  const bits = parseInt(bitsRaw, 10);
  const start = ipToInt(addr);
  if (start === null || !Number.isInteger(bits) || bits < 8 || bits > 32) return null;
  const size = 2 ** (32 - bits);
  return [start, start + size - 1];
}

const countryCsv = await fetchDb('dbip-country-lite');
const asnCsv = await fetchDb('dbip-asn-lite');
if (!countryCsv || !asnCsv) writeEmpty('download failed for all attempted months');

// --- country.bin -------------------------------------------------------------
const countries = [];
const countryIdx = new Map();
const countryRecords = [];
for (const line of countryCsv.split('\n')) {
  if (!line || line.includes(':')) continue;  // skip empty + IPv6 rows
  const f = csvFields(line.trim());
  if (f.length < 3) continue;
  const start = ipToInt(f[0]);
  const end = ipToInt(f[1]);
  const cc = f[2].trim().toUpperCase();
  if (start === null || end === null || cc.length !== 2) continue;
  let idx = countryIdx.get(cc);
  if (idx === undefined) {
    idx = countries.push(cc) - 1;
    countryIdx.set(cc, idx);
  }
  countryRecords.push([start, end, idx]);
}
if (countries.length > 255) writeEmpty(`country index overflow (${countries.length})`);
countryRecords.sort((a, b) => a[0] - b[0]);
const countryBuf = Buffer.alloc(countryRecords.length * 9);
countryRecords.forEach(([start, end, idx], i) => {
  countryBuf.writeUInt32BE(start, i * 9);
  countryBuf.writeUInt32BE(end, i * 9 + 4);
  countryBuf.writeUInt8(idx, i * 9 + 8);
});

// --- asn.bin -----------------------------------------------------------------
const dcOrgs = [];
const dcOrgIdx = new Map();
const asnRecords = [];
let dcRangeCount = 0;
for (const line of asnCsv.split('\n')) {
  if (!line || line.includes(':')) continue;
  const f = csvFields(line.trim());
  if (f.length < 4) continue;
  const start = ipToInt(f[0]);
  const end = ipToInt(f[1]);
  const org = f.slice(3).join(',').trim();  // org is the tail even if unquoted commas slipped through
  if (start === null || end === null) continue;
  let idx = 0xFFFF;
  const dcLabel = datacenterLabel(f[2].trim(), org, start);
  if (dcLabel) {
    idx = dcOrgIdx.get(dcLabel);
    if (idx === undefined) {
      if (dcOrgs.length >= 0xFFFE) {
        idx = 0xFFFF;  // org table full — treat overflow as non-DC rather than corrupt
      } else {
        idx = dcOrgs.push(dcLabel) - 1;
        dcOrgIdx.set(dcLabel, idx);
      }
    }
    if (idx !== 0xFFFF) dcRangeCount++;
  }
  asnRecords.push([start, end, idx]);
}
asnRecords.sort((a, b) => a[0] - b[0]);
const asnBuf = Buffer.alloc(asnRecords.length * 10);
asnRecords.forEach(([start, end, idx], i) => {
  asnBuf.writeUInt32BE(start, i * 10);
  asnBuf.writeUInt32BE(end, i * 10 + 4);
  asnBuf.writeUInt16BE(idx, i * 10 + 8);
});

// --- crawler-asn.bin ---------------------------------------------------------
// Same 10-byte record layout as asn.bin, but the u16 holds an index into
// meta.crawlerAsns (the ASN NUMBER list), not an org-name table.
const crawlerAsns = [];
const crawlerRecords = [];
if (process.env.SKIP_CRAWLER_ASN) {
  console.log('[geodb] SKIP_CRAWLER_ASN set — crawler-asn.bin will be empty');
} else {
  for (const { asn, name } of CRAWLER_ASNS) {
    const prefixes = await fetchAsnPrefixes(asn);
    if (!prefixes || prefixes.length === 0) {
      // Fail open for THIS asn: server.js falls back to the UA-only (capped)
      // whitelist rather than treating the crawler as a fake.
      console.error(`[geodb] WARNING: no prefixes for AS${asn} (${name}) — `
        + 'its UA whitelist will be honoured uncorroborated (still rate-capped)');
      continue;
    }
    const idx = crawlerAsns.push(asn) - 1;
    let kept = 0;
    for (const cidr of prefixes) {
      const range = cidrToRange(cidr);
      if (!range) continue;
      crawlerRecords.push([range[0], range[1], idx]);
      kept++;
    }
    console.log(`[geodb] AS${asn} (${name}): ${kept} IPv4 prefixes`);
  }
}
crawlerRecords.sort((a, b) => a[0] - b[0]);
const crawlerBuf = Buffer.alloc(crawlerRecords.length * 10);
crawlerRecords.forEach(([start, end, idx], i) => {
  crawlerBuf.writeUInt32BE(start, i * 10);
  crawlerBuf.writeUInt32BE(end, i * 10 + 4);
  crawlerBuf.writeUInt16BE(idx, i * 10 + 8);
});

// --- apple-relay.bin ---------------------------------------------------------
// iCloud Private Relay egress (Apple's published list, IPv4 only). ~81 % of it
// sits in Cloudflare/Akamai ASNs that the DC keywords classify as hosting, so
// without this list anonymous Safari users on Private Relay would get the
// short hosting pass and lose Google Analytics (D96). Records: u32 start,
// u32 end (8 bytes), sorted, adjacent ranges merged. Fails open: no file =>
// no exemption (server.js behaves exactly as before).
const RELAY_URL = 'https://mask-api.icloud.com/egress-ip-ranges.csv';
let relayRecords = [];
if (process.env.SKIP_APPLE_RELAY) {
  console.log('[geodb] SKIP_APPLE_RELAY set — apple-relay.bin not written');
} else {
  try {
    const res = await fetch(RELAY_URL, { redirect: 'follow' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = [];
    for (const line of (await res.text()).split('\n')) {
      const cidr = line.split(',')[0].trim();
      if (!cidr || cidr.includes(':')) continue;
      const range = cidrToRange(cidr);
      if (range) raw.push(range);
    }
    raw.sort((a, b) => a[0] - b[0]);
    for (const r of raw) {
      const last = relayRecords[relayRecords.length - 1];
      if (last && r[0] <= last[1] + 1) {
        last[1] = Math.max(last[1], r[1]);
      } else {
        relayRecords.push([r[0], r[1]]);
      }
    }
    // Apple publishes ~42k IPv4 prefixes (they merge to ~1k ranges); far fewer
    // means a truncated or changed download.
    if (raw.length < 10000) throw new Error(`only ${raw.length} prefixes — refusing a truncated list`);
    console.log(`[geodb] Apple Private Relay: ${raw.length} IPv4 prefixes -> ${relayRecords.length} ranges`);
  } catch (err) {
    console.error(`[geodb] WARNING: Apple Private Relay list failed (${err.message}) — no relay exemption`);
    relayRecords = [];
  }
}
if (relayRecords.length > 0) {
  const relayBuf = Buffer.alloc(relayRecords.length * 8);
  relayRecords.forEach(([start, end], i) => {
    relayBuf.writeUInt32BE(start, i * 8);
    relayBuf.writeUInt32BE(end, i * 8 + 4);
  });
  writeFileSync(join(OUT_DIR, 'apple-relay.bin'), relayBuf);
}

// --- write -------------------------------------------------------------------
writeFileSync(join(OUT_DIR, 'country.bin'), countryBuf);
writeFileSync(join(OUT_DIR, 'asn.bin'), asnBuf);
writeFileSync(join(OUT_DIR, 'crawler-asn.bin'), crawlerBuf);
writeFileSync(join(OUT_DIR, 'meta.json'), JSON.stringify({
  built: new Date().toISOString(),
  source: 'DB-IP lite (db-ip.com, CC BY 4.0); crawler ASNs via RIPEstat',
  countryRanges: countryRecords.length,
  asnRanges: asnRecords.length,
  dcRanges: dcRangeCount,
  crawlerAsnRanges: crawlerRecords.length,
  appleRelayRanges: relayRecords.length,
  countries,
  dcOrgs,
  crawlerAsns,
}));
console.log(`[geodb] wrote ${countryRecords.length} country ranges, `
  + `${asnRecords.length} ASN ranges (${dcRangeCount} datacenter, ${dcOrgs.length} orgs), `
  + `${crawlerRecords.length} crawler-ASN ranges (AS${crawlerAsns.join(', AS') || 'none'}) to ${OUT_DIR}`);
