#!/usr/bin/env bash
# Mints a litehop-reviewer GitHub App installation access token and prints
# it, alone, on stdout. Uses curl rather than `gh api` for the two calls
# below: `gh` always sends `Authorization: token <...>`, but minting an App
# token requires an App JWT sent as `Authorization: Bearer <jwt>`, which `gh`
# has no flag to produce.
#
# No caching: one mint per caller. A cache file is state to invalidate for no
# measurable gain.
set -euo pipefail

APP_ID="${BEEP_REVIEWER_APP_ID:?BEEP_REVIEWER_APP_ID must be set to the litehop-reviewer App ID}"
APP_KEY="${BEEP_REVIEWER_APP_KEY:?BEEP_REVIEWER_APP_KEY must be set to the litehop-reviewer private key path}"

# The operator's own settings.local.json stores this path with a literal
# leading `~`, which bash does not expand once it has come through a
# variable rather than a bare word.
APP_KEY="${APP_KEY/#\~/$HOME}"

if [ ! -r "$APP_KEY" ]; then
  echo "gh-app-token: cannot read private key at $APP_KEY" >&2
  exit 1
fi

b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

IAT=$(( $(date +%s) - 60 ))
EXP=$(( IAT + 540 ))

HEADER=$(jq -cn '{alg:"RS256",typ:"JWT"}' | b64url)
PAYLOAD=$(jq -cn --arg iss "$APP_ID" --argjson iat "$IAT" --argjson exp "$EXP" \
  '{iat:$iat,exp:$exp,iss:$iss}' | b64url)
SIGNING_INPUT="$HEADER.$PAYLOAD"
SIGNATURE=$(printf '%s' "$SIGNING_INPUT" | openssl dgst -sha256 -binary -sign "$APP_KEY" | b64url)
JWT="$SIGNING_INPUT.$SIGNATURE"

# Authorization is sent via a stdin-fed curl config (`-K -`) rather than a
# `-H` argument so the JWT never appears in this process's argv, readable
# via `ps` by any process running as the same user for the call's lifetime
# (same pattern gh-app-review.sh uses for the installation token).
curl_auth_config() {
  printf 'header = "Authorization: Bearer %s"\n' "$JWT"
  printf 'header = "Accept: application/vnd.github+json"\n'
}

INSTALLATION_ID=$(curl_auth_config | curl -sSf -K - \
  https://api.github.com/repos/litehop/beep/installation | jq -r '.id')

if [ -z "$INSTALLATION_ID" ] || [ "$INSTALLATION_ID" = "null" ]; then
  echo "gh-app-token: could not resolve an installation id for litehop/beep" >&2
  exit 1
fi

TOKEN=$(curl_auth_config | curl -sSf -X POST -K - \
  "https://api.github.com/app/installations/$INSTALLATION_ID/access_tokens" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "gh-app-token: access-token response did not contain a token" >&2
  exit 1
fi

printf '%s\n' "$TOKEN"
