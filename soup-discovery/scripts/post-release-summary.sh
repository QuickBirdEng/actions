#!/usr/bin/env bash
# Announce a new assessment: the headline numbers, what moved since the previous release, and
# the VDR itself.
#
# Attaching needs files:write on the bot. Without it the post still goes out with a link — a
# summary nobody sees is worse than one without an attachment.
#
# Usage: post-release-summary.sh <owner/repo> <tag> <assessed.cdx.json> [vdr.pdf] [units.json]
# Env:   SLACK_TOKEN, SLACK_CHANNEL (both required to post), PRODUCT, PYTHON, GH_TOKEN

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:?usage: post-release-summary.sh <owner/repo> <tag> <bom> [vdr] [units]}"
TAG="${2:?tag required}"
BOM="${3:?assessed BOM required}"
VDR="${4:-}"
UNITS="${5:-}"
PY="${PYTHON:-python3}"
PRODUCT="${PRODUCT:-$(basename "$REPO")}"

for t in gh jq curl; do command -v "$t" >/dev/null 2>&1 || { echo "::error::$t required" >&2; exit 1; }; done
[[ -s "$BOM" ]] || { echo "::error::assessed BOM not found: $BOM" >&2; exit 1; }

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

SUM_ARGS=("$BOM"); [[ -n "$UNITS" && -f "$UNITS" ]] && SUM_ARGS+=(--units "$UNITS")
"$PY" "$HERE/summarise-bom.py" "${SUM_ARGS[@]}" --out "$WORK/now.json" || exit 1

# Ordered by publication, not by tag name: tag order is a convention, not a timeline.
PREV=$(gh api "repos/$REPO/releases?per_page=100" 2>/dev/null | jq -r --arg tag "$TAG" '
  [ .[] | select(.draft | not)
    | { tag: .tag_name, published: .published_at,
        sbom: ([ .assets[] | select(.name | test("^sbom-.*\\.cdx\\.json$")) | .url ][0] // null) }
    | select(.sbom != null) ]
  | sort_by(.published)
  | (map(.tag) | index($tag)) as $i
  | if $i == null or $i == 0 then empty else .[$i - 1] end' 2>/dev/null)

DELTA=""
if [[ -n "$PREV" ]]; then
  PREV_TAG=$(jq -r '.tag' <<<"$PREV")
  if gh api -H "Accept: application/octet-stream" "$(jq -r '.sbom' <<<"$PREV")" > "$WORK/prev.cdx.json" 2>/dev/null \
     && [[ -s "$WORK/prev.cdx.json" ]] \
     && "$PY" "$HERE/summarise-bom.py" "$WORK/prev.cdx.json" --out "$WORK/prev.json" 2>/dev/null; then
    DELTA=$(jq -r -n --slurpfile a "$WORK/prev.json" --slurpfile b "$WORK/now.json" --arg t "$PREV_TAG" '
      ($a[0]) as $p | ($b[0]) as $n
      | def d($k): ($n[$k] // 0) - ($p[$k] // 0);
        def s($v): if $v > 0 then "+\($v)" else "\($v)" end;
        [ (if d("beyond_limit") != 0 then "beyond limit \(s(d("beyond_limit")))" else empty end),
          (if d("critical") != 0 then "Critical \(s(d("critical")))" else empty end),
          (if d("high") != 0 then "High \(s(d("high")))" else empty end),
          (if d("stale") != 0 then "stale \(s(d("stale")))" else empty end),
          (if d("kev") != 0 then "KEV \(s(d("kev")))" else empty end) ]
      | if length == 0 then "_Unchanged against `\($t)`._"
        else "_Against `\($t)`: " + join(" · ") + "._" end' 2>/dev/null)
  fi
fi

{
  echo ":package: *$PRODUCT $TAG — new assessment*"
  echo ""
  "$PY" "$HERE/summarise-bom.py" "${SUM_ARGS[@]}" --render "" | sed 's/^/   /'
  [[ -n "$DELTA" ]] && { echo ""; echo "$DELTA"; }
  echo ""
  echo "<https://github.com/$REPO/releases/tag/$TAG|Release $TAG>"
} > "$WORK/msg.txt"

if [[ -z "${SLACK_TOKEN:-}" || -z "${SLACK_CHANNEL:-}" ]]; then
  echo "no Slack channel or token — message not posted:" >&2
  cat "$WORK/msg.txt" >&2
  exit 0
fi

post_text() {
  jq -n --arg ch "$SLACK_CHANNEL" --arg t "$(cat "$WORK/msg.txt")" \
    '{channel:$ch, text:$t, mrkdwn:true}' \
  | curl -sS --retry 3 --retry-delay 2 -X POST https://slack.com/api/chat.postMessage \
      -H "Authorization: Bearer $SLACK_TOKEN" \
      -H 'Content-Type: application/json; charset=utf-8' --data @- \
  | jq -e '.ok' >/dev/null
}

# files.upload is retired; the flow is get-url, PUT, complete.
upload_with_vdr() {
  [[ -n "$VDR" && -s "$VDR" ]] || return 1
  local name="vdr-$TAG.pdf" len url fid
  len=$(wc -c < "$VDR" | tr -d ' ')
  local got; got=$(curl -sS -X POST https://slack.com/api/files.getUploadURLExternal \
      -H "Authorization: Bearer $SLACK_TOKEN" \
      --data-urlencode "filename=$name" --data-urlencode "length=$len")
  jq -e '.ok' <<<"$got" >/dev/null || {
    echo "::warning::Slack upload URL refused: $(jq -r '.error // "unknown"' <<<"$got")" >&2; return 1; }
  url=$(jq -r '.upload_url' <<<"$got"); fid=$(jq -r '.file_id' <<<"$got")
  curl -sS -f -X POST "$url" -F "file=@$VDR" >/dev/null || return 1
  local done_
  done_=$(jq -n --arg id "$fid" --arg ttl "$name" --arg ch "$SLACK_CHANNEL" --arg c "$(cat "$WORK/msg.txt")" \
            '{files:[{id:$id,title:$ttl}], channel_id:$ch, initial_comment:$c}' \
          | curl -sS -X POST https://slack.com/api/files.completeUploadExternal \
              -H "Authorization: Bearer $SLACK_TOKEN" \
              -H 'Content-Type: application/json; charset=utf-8' --data @-)
  jq -e '.ok' <<<"$done_" >/dev/null || {
    echo "::warning::Slack upload completion refused: $(jq -r '.error // "unknown"' <<<"$done_")" >&2; return 1; }
  echo "posted with $name attached" >&2
}

if upload_with_vdr; then
  exit 0
fi
echo "::warning::posting without the VDR attached — the bot needs the files:write scope" >&2
post_text || { echo "::error::Slack post failed — the assessment exists, nobody was told" >&2; exit 1; }
echo "posted (link only)" >&2
