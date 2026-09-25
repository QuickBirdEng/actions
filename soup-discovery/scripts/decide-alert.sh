#!/usr/bin/env bash
# Should this alert be posted, or has it already been said?
#
# The monitor runs daily and the blocks are built from the current state, so an unchanged situation
# produces the identical message every morning. A channel that repeats itself is a channel people
# stop reading, and then the day the message changes goes unnoticed too.
#
# The rules, in order:
#
#   an actively exploited vulnerability posts every run. It carries a 24-hour reporting clock and
#   is not something to go quiet about because it was also true yesterday.
#   a message whose text differs from the last one posted goes out: a new finding, a changed count,
#   a deadline that has passed.
#   an unchanged message goes out again once a week, so a standing problem stays visible without
#   being repeated daily. That repeat says so, or a reader takes it for something new.
#
# The comparison is the message text, not a per-item ledger. Every change worth telling someone
# about changes the text, and the text is what they read.
#
# Usage: decide-alert.sh <alert.txt> <record.json> <state.json> [items.json]
#        prints post=true|false; rewrites <state.json>
#        ALERT_REPEAT_DAYS  days before an unchanged alert is repeated (default 7)
#        ALERT_NOW          ISO timestamp, for reproducible tests
#
# items.json is compose-alert.sh's ledger of everything open this run, key -> level. It is
# carried in the state so the next run can tell new from standing. Written here rather than
# there for one reason: an item must not count as announced until the message carrying it was
# actually sent, which is the same rule the digest already follows.

set -uo pipefail

ALERT="${1:?missing alert file}"
RECORD="${2:?missing record}"
STATE="${3:?missing state file}"
ITEMS="${4:-}"
REPEAT_DAYS="${ALERT_REPEAT_DAYS:-7}"
NOW="${ALERT_NOW:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

if [[ ! -s "$ALERT" ]]; then
  echo "post=false"
  exit 0
fi

DIGEST=$(shasum -a 256 "$ALERT" 2>/dev/null | cut -d' ' -f1)
[[ -n "$DIGEST" ]] || DIGEST=$(sha256sum "$ALERT" | cut -d' ' -f1)

PREV_DIGEST=""; PREV_AT=""
if [[ -f "$STATE" ]] && jq -e . "$STATE" >/dev/null 2>&1; then
  PREV_DIGEST=$(jq -r '.digest // ""' "$STATE")
  PREV_AT=$(jq -r '.posted_at // ""' "$STATE")
fi

VERDICT=$(jq -r '.verdict // ""' "$RECORD" 2>/dev/null)

days_since() {
  [[ -n "$1" ]] || { echo 99999; return; }
  python3 - "$1" "$NOW" <<'PY' 2>/dev/null || echo 99999
import sys, datetime
def p(s): return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
try:
    print(int((p(sys.argv[2]) - p(sys.argv[1])).total_seconds() // 86400))
except Exception:
    print(99999)
PY
}

WHY=""
if [[ "$VERDICT" == "kev-findings" ]]; then
  WHY="an actively exploited vulnerability is not muted"
elif [[ "$DIGEST" != "$PREV_DIGEST" ]]; then
  WHY="the message changed"
else
  AGE=$(days_since "$PREV_AT")
  if [[ "$AGE" -ge "$REPEAT_DAYS" ]]; then
    WHY="unchanged for $AGE day(s), repeated so it stays visible"
    # Without this the reader takes a weekly repeat for a new problem.
    printf '\n_Unchanged since %s. Repeated because it is still open, not because anything moved._\n' \
      "${PREV_AT%%T*}" >> "$ALERT"
    DIGEST=$(shasum -a 256 "$ALERT" 2>/dev/null | cut -d' ' -f1)
    [[ -n "$DIGEST" ]] || DIGEST=$(sha256sum "$ALERT" | cut -d' ' -f1)
  fi
fi

if [[ -z "$WHY" ]]; then
  echo "post=false"
  echo "  alert unchanged and last posted ${PREV_AT:-never} — not repeating" >&2
  exit 0
fi

# Only a posted message updates the record. Recording a digest that was never sent would suppress
# the next run, which is the one failure this must not have.
NEW_ITEMS='{}'
if [[ -n "$ITEMS" && -f "$ITEMS" ]]; then
  NEW_ITEMS=$(jq -c '.' "$ITEMS" 2>/dev/null) || NEW_ITEMS='{}'
  [[ -n "$NEW_ITEMS" && "$NEW_ITEMS" != "null" ]] || NEW_ITEMS='{}'
fi
jq -n --arg d "$DIGEST" --arg at "$NOW" --argjson it "$NEW_ITEMS" \
  '{digest: $d, posted_at: $at, items: $it}' > "$STATE"
echo "post=true"
echo "  posting: $WHY" >&2
