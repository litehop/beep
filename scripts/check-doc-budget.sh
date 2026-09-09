#!/usr/bin/env bash
# Pre-push gate: enforces word budgets on durable docs as a RATCHET.
#
# Why words and not lines (measured 2026-08-21): line count is not invariant
# under reflow, so an agent that hits a line cap can join lines and pass with
# zero content change. Worse, it already misranks the corpus — at the time of
# writing docs/decisions/proto-adapter-codegen.md was 36 lines / 569 words
# (185 chars/line) while install-script-ux.md was 56 lines / 420 words
# (60 chars/line), so a 45-line budget would have passed the longer document
# and failed the shorter one. `wc -w` is invariant under reflow, line joining,
# indentation and blank lines. It is also the unit the rest of the project
# already uses (mayor-dispatch-template.md caps returns at 300/400 words),
# and at ~1.3 tokens/word it tracks the cost this gate exists to control.
#
# RATCHET, not ceiling: a file over budget may shrink or hold, never grow.
# Pre-existing debt therefore never wedges a push, and compression work is
# never blocked. Only accretion fails.
#
# Fenced code blocks are excluded from the count — code is not prose verbosity.
# `kind: postmortem` docs are exempt: they record an incident at a point in
# time and are not maintained down.
#
# Deliberately NOT enforced: line width. Words are reflow-invariant, so wrap
# style cannot affect this gate; adding a wrap rule would only conflate a
# formatting proxy with a content measure again.
#
# Usage: scripts/check-doc-budget.sh [base-ref]   (default: origin/main)

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BASE_REF="${1:-origin/main}"
BASE=$(git merge-base "$BASE_REF" HEAD)

# Word budgets per directory. docs/decisions/ is anchored to the tight cluster
# of ADRs that work (crio 225, webhook 235, sqlite 263, rust-api 282,
# custom-bin 306), not to the corpus mean — 400 is ~30% above that cluster.
#
# ai/dashboard.md also carries a ~40-line ceiling in mayor-bootstrap.md. That rule
# is about fitting one screen so a returning operator re-orients fast; this
# one is about content volume. They are complementary — a dashboard reflowed
# to 20 long lines would satisfy the line rule and still be bloated.
budget_for() {
  case "$1" in
    docs/decisions/*)      echo 400 ;;
    ai/dashboard.md)       echo 400 ;;
    *)                     echo 0 ;;   # 0 = not budgeted
  esac
}

# Strip fenced code blocks, then count words.
count_words() { awk '/^```/ { f = !f; next } !f' | wc -w | tr -d ' '; }

violations=0
net_delta=0

while IFS= read -r f; do
  [ -n "$f" ] || continue
  budget=$(budget_for "$f")
  [ "$budget" -eq 0 ] && continue

  if [ -f "$f" ]; then
    new=$(count_words < "$f")
    # Exempt incident writeups; they are dated records, not maintained docs.
    if head -20 "$f" | grep -qE '^kind: postmortem[[:space:]]*$'; then
      continue
    fi
  else
    new=0   # deleted
  fi

  if git cat-file -e "$BASE:$f" 2>/dev/null; then
    old=$(git show "$BASE:$f" | count_words)
  else
    old=0   # new file
  fi

  net_delta=$(( net_delta + new - old ))

  if [ "$new" -gt "$budget" ] && [ "$new" -gt "$old" ]; then
    printf 'DOC BUDGET: %s is %d words (budget %d, was %d, +%d).\n' \
      "$f" "$new" "$budget" "$old" "$(( new - old ))" >&2
    violations=$(( violations + 1 ))
  fi
done < <(
  # Tracked changes vs the fork point, plus untracked new docs. Without the
  # second list a brand-new over-budget doc passes a manual run: `git diff`
  # only sees tracked paths. The push gate would still catch it (by then it
  # is committed), but a silent pass before that teaches the wrong lesson.
  {
    git diff --name-only "$BASE" -- '*.md'
    git ls-files --others --exclude-standard -- '*.md'
  } | sort -u
)

if [ "$violations" -gt 0 ]; then
  printf 'DOC BUDGET: %d over-budget doc(s) grew. Cut words, do not reflow —\n' \
    "$violations" >&2
  printf '  this gate counts words, so joining lines changes nothing.\n' >&2
  printf '  See CLAUDE.md Rule 16 and `git show e10ca358`.\n' >&2
  exit 1
fi

# Reported, not enforced: a split that moves words from one budgeted doc into
# a new one nets to ~zero here while every file passes individually. Whether
# that split is a real decomposition or evasion is a judgment call for the
# reviewer, not for this script.
if [ "$net_delta" -ne 0 ]; then
  printf 'doc-budget: ok (net %+d words across budgeted docs)\n' "$net_delta"
else
  printf 'doc-budget: ok\n'
fi
