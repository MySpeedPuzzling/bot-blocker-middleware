#!/bin/bash
# Test script for page scraping detection
# Runs against bot-blocker directly on port 3000 using simulated headers
#
# Usage: ./test-scraper.sh [bot-blocker-url]
# Default: http://localhost:3000

set -e

URL="${1:-http://localhost:3000}"
PASS=0
FAIL=0
TEST_IP="192.168.99.1"
TEST_UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

send_request() {
  local ip="$1"
  local ua="$2"
  local uri="$3"
  curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Forwarded-For: $ip" \
    -H "X-Forwarded-User-Agent: $ua" \
    -H "X-Forwarded-URI: $uri" \
    "$URL"
}

assert_status() {
  local expected="$1"
  local actual="$2"
  local desc="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  PASS: $desc (got $actual)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc (expected $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

echo "============================================"
echo "Bot Blocker - Page Scraping Detection Tests"
echo "Target: $URL"
echo "============================================"
echo ""

# -------------------------------------------------------------------
echo "TEST 1: Known scraper UA is immediately blocked"
# -------------------------------------------------------------------
status=$(send_request "$TEST_IP" "MySpeedPuzzling-Research-Scraper/1.0 (academic research)" "/en/puzzle/test-123")
assert_status "403" "$status" "Scraper UA gets 403"

# Use a different IP for remaining tests to avoid interference
TEST_IP="10.0.0.1"

# -------------------------------------------------------------------
echo ""
echo "TEST 2: Normal puzzle browsing is allowed (under threshold)"
# -------------------------------------------------------------------
for i in $(seq 1 4); do
  status=$(send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/puzzle-$i")
  assert_status "200" "$status" "Puzzle request $i allowed"
done

# -------------------------------------------------------------------
echo ""
echo "TEST 3: Puzzle scraping triggers 429 on 1st strike (threshold=5 in test)"
# -------------------------------------------------------------------
# Need >=5 unique IDs to trigger. Send 4 silently, then 5th triggers.
TEST_IP="10.0.0.2"
for i in $(seq 1 4); do
  send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/strike1-$i" > /dev/null
done
status=$(send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/strike1-5")
assert_status "429" "$status" "5th unique puzzle triggers 429 (strike 1)"

# -------------------------------------------------------------------
echo ""
echo "TEST 4: 2nd strike also returns 429"
# -------------------------------------------------------------------
# Window was reset after strike 1 (with strike1-5 still in Set, so 4 new IDs needed).
for i in $(seq 1 3); do
  send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/strike2-$i" > /dev/null
done
status=$(send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/strike2-4")
assert_status "429" "$status" "2nd strike triggers 429"

# -------------------------------------------------------------------
echo ""
echo "TEST 5: 3rd strike triggers permaban (403)"
# -------------------------------------------------------------------
# Window reset with strike2-4 in Set, need 4 more new IDs.
for i in $(seq 1 3); do
  send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/strike3-$i" > /dev/null
done
status=$(send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/strike3-4")
assert_status "403" "$status" "3rd strike triggers 403 permaban"

# Verify banned — any request from this IP should be 403
status=$(send_request "$TEST_IP" "$TEST_UA" "/")
assert_status "403" "$status" "Subsequent request from banned IP is 403"

# -------------------------------------------------------------------
echo ""
echo "TEST 6: Profile scraping works the same way"
# -------------------------------------------------------------------
TEST_IP="10.0.0.3"
for i in $(seq 1 4); do
  send_request "$TEST_IP" "$TEST_UA" "/en/player-profile/player-$i" > /dev/null
done
status=$(send_request "$TEST_IP" "$TEST_UA" "/en/player-profile/player-5")
assert_status "429" "$status" "Profile scraping triggers 429 on 1st strike"

# -------------------------------------------------------------------
echo ""
echo "TEST 7: Different UA on same IP tracks independently (shared WiFi)"
# -------------------------------------------------------------------
TEST_IP="10.0.0.4"
UA1="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1"
UA2="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0 Safari/537.36"

# Each UA sends 4 unique (under threshold of 5 with >=) — neither should trigger
for i in $(seq 1 4); do
  send_request "$TEST_IP" "$UA1" "/en/puzzle/shared-a-$i" > /dev/null
  send_request "$TEST_IP" "$UA2" "/en/puzzle/shared-b-$i" > /dev/null
done
# 4 unique each, both under threshold — should still be allowed
status1=$(send_request "$TEST_IP" "$UA1" "/en/puzzle/shared-a-1")
status2=$(send_request "$TEST_IP" "$UA2" "/en/puzzle/shared-b-1")
assert_status "200" "$status1" "UA1 on shared IP still under threshold (4 unique, repeated ID)"
assert_status "200" "$status2" "UA2 on shared IP still under threshold (4 unique, repeated ID)"

# -------------------------------------------------------------------
echo ""
echo "TEST 8: Repeated same puzzle ID does NOT count as unique"
# -------------------------------------------------------------------
TEST_IP="10.0.0.5"
for i in $(seq 1 20); do
  send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/same-puzzle-id" > /dev/null
done
status=$(send_request "$TEST_IP" "$TEST_UA" "/en/puzzle/same-puzzle-id")
assert_status "200" "$status" "20 requests to same puzzle ID still allowed"

# -------------------------------------------------------------------
echo ""
echo "TEST 9: All locale variants are detected"
# -------------------------------------------------------------------
TEST_IP="10.0.0.6"
status=$(send_request "$TEST_IP" "$TEST_UA" "/puzzle/locale-cs-1")
assert_status "200" "$status" "CS puzzle route matched"
status=$(send_request "$TEST_IP" "$TEST_UA" "/es/puzzle/locale-es-1")
assert_status "200" "$status" "ES puzzle route matched"
status=$(send_request "$TEST_IP" "$TEST_UA" "/fr/resoudre-puzzle/locale-fr-1")
assert_status "200" "$status" "FR solving puzzle route matched"
status=$(send_request "$TEST_IP" "$TEST_UA" "/de/spieler-profil/locale-de-1")
assert_status "200" "$status" "DE profile route matched"
status=$(send_request "$TEST_IP" "$TEST_UA" "/profil-hrace/locale-cs-prof")
assert_status "200" "$status" "CS profile route matched"

# -------------------------------------------------------------------
echo ""
echo "============================================"
echo "Results: $PASS passed, $FAIL failed"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
