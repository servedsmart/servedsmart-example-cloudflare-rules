#!/usr/bin/env bash
###
# File: set-headers.sh
# Author: Leopold Meinel (leo@meinel.dev)
# -----
# Copyright (c) 2025 Leopold Meinel & contributors
# SPDX ID: MIT
# URL: https://opensource.org/licenses/MIT
# -----
###

# Fail on error
set -e

# Source config
SCRIPT_DIR="$(dirname -- "$(readlink -f -- "${0}")")"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}"/set-headers.conf

# Define variables
## https://content-security-policy.com/
RULES_CSP_DEFAULT=(
    "default-src 'none'"
    "script-src 'self' 'unsafe-inline'"
    "style-src 'self' 'unsafe-inline'"
    "img-src 'self' blob: data:"
    "connect-src 'self'"
    "font-src 'self'"
    "object-src 'self'"
    "media-src blob:"
    "frame-src blob: https://www.youtube-nocookie.com"
    "child-src blob: https://www.youtube-nocookie.com"
    "form-action 'none'"
    "frame-ancestors 'none'"
    "base-uri 'none'"
    "worker-src 'none'"
    "manifest-src 'self'"
    "prefetch-src 'none'"
    "require-trusted-types-for 'script'"
    "trusted-types 'none'"
    "upgrade-insecure-requests"
    "block-all-mixed-content"
)
### https://github.com/sveltia/sveltia-cms?tab=readme-ov-file#setting-up-content-security-policy
RULES_CSP_CMS=(
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com"
    "font-src 'self' https://fonts.gstatic.com"
    "img-src 'self' blob: data: https://*.githubusercontent.com"
    "media-src blob:"
    "frame-src blob: https://www.youtube-nocookie.com"
    "child-src blob: https://www.youtube-nocookie.com"
    "script-src 'self' https://unpkg.com"
    "connect-src 'self' blob: data: https://unpkg.com https://api.github.com https://www.githubstatus.com"
    "upgrade-insecure-requests"
    "block-all-mixed-content"
)
RULES_CSP_DEFAULT_LENGTH="${#RULES_CSP_DEFAULT[@]}"
for ((i = 0; i < RULES_CSP_DEFAULT_LENGTH; i++)); do
    if ((i != RULES_CSP_DEFAULT_LENGTH - 1)); then
        CSP_DEFAULT+="${RULES_CSP_DEFAULT[${i}]}; "
        continue
    fi
    #### Join into string
    CSP_DEFAULT+="${RULES_CSP_DEFAULT[${i}]}"
done
RULES_CSP_CMS_LENGTH="${#RULES_CSP_CMS[@]}"
for ((i = 0; i < RULES_CSP_CMS_LENGTH; i++)); do
    if ((i != RULES_CSP_CMS_LENGTH - 1)); then
        CSP_CMS+="${RULES_CSP_CMS[${i}]}; "
        continue
    fi
    #### Join into string
    CSP_CMS+="${RULES_CSP_CMS[${i}]}"
done
## https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy
RULES_PP_DEFAULT=(
    # https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md#standardized-features
    "accelerometer=()"
    "ambient-light-sensor=()"
    "attribution-reporting=()"
    "autoplay=()"
    "battery=()"
    "bluetooth=()"
    "camera=()"
    "ch-ua=()"
    "ch-ua-arch=()"
    "ch-ua-bitness=()"
    "ch-ua-full-version=()"
    "ch-ua-full-version-list=()"
    "ch-ua-high-entropy-values=()"
    "ch-ua-mobile=()"
    "ch-ua-model=()"
    "ch-ua-platform=()"
    "ch-ua-platform-version=()"
    "ch-ua-wow64=()"
    "compute-pressure=()"
    "cross-origin-isolated=()"
    "direct-sockets=()"
    "display-capture=()"
    "encrypted-media=()"
    "execution-while-not-rendered=()"
    "execution-while-out-of-viewport=()"
    'fullscreen=(self \"https://www.youtube-nocookie.com\")'
    "geolocation=()"
    "gyroscope=()"
    "hid=()"
    "identity-credentials-get=()"
    "idle-detection=()"
    "keyboard-map=()"
    "magnetometer=()"
    "mediasession=()"
    "microphone=()"
    "midi=()"
    "navigation-override=()"
    "otp-credentials=()"
    "payment=()"
    "picture-in-picture=()"
    "publickey-credentials-get=()"
    "screen-wake-lock=()"
    "serial=()"
    "sync-xhr=()"
    "storage-access=()"
    "usb=()"
    "web-share=()"
    "window-management=()"
    "xr-spatial-tracking=()"
    # https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md#proposed-features
    "clipboard-read=()"
    "clipboard-write=(self)"
    "deferred-fetch=()"
    "gamepad=()"
    "shared-autofill=()"
    "speaker-selection=()"
    # https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md#experimental-features
    "all-screens-capture=()"
    "browsing-topics=()"
    "captured-surface-control=()"
    "conversion-measurement=()"
    "digital-credentials-get=()"
    "focus-without-user-activation=()"
    "join-ad-interest-group=()"
    "local-fonts=()"
    "run-ad-auction=()"
    "smart-card=()"
    "sync-script=()"
    "trust-token-redemption=()"
    "unload=()"
    "vertical-scroll=()"
    # https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md#retired-features
    "document-domain=()"
    "window-placement=()"
)
RULES_PP_DEFAULT_LENGTH="${#RULES_PP_DEFAULT[@]}"
for ((i = 0; i < RULES_PP_DEFAULT_LENGTH; i++)); do
    if ((i != RULES_PP_DEFAULT_LENGTH - 1)); then
        PP_DEFAULT+="${RULES_PP_DEFAULT[${i}]}, "
        continue
    fi
    #### Join into string
    PP_DEFAULT+="${RULES_PP_DEFAULT[${i}]}"
done
## Generate EXPRESSION_CMS with languages used in REPO_URL_EXTERNAL
EXPRESSION_CMS="(starts_with(http.request.uri.path, \\\"/edit-cms\\\"))"
OUTPUT_DIR="${SCRIPT_DIR}"/external
git clone -b main "${REPO_URL_EXTERNAL}" "${OUTPUT_DIR}"
DEFAULT_LOCALE="$(tomlq -cr ".defaultContentLanguage" "${OUTPUT_DIR}"/config/_default/hugo.toml)"
for file in "${OUTPUT_DIR}"/config/_default/languages.*.toml; do
    LOCALE="$(basename "${file}" .toml | cut -d. -f2)"
    if [[ "${LOCALE}" != "${DEFAULT_LOCALE}" ]]; then
        EXPRESSION_CMS+=" or (starts_with(http.request.uri.path, \\\"/${LOCALE}/edit-cms\\\"))"
    fi
done
## https://developers.cloudflare.com/ruleset-engine/rulesets-api/create/
JSON_REQUEST_FULL="$(
    cat <<EOF
{
  "name": "Secure HTTP Response Headers",
  "description": "Generated by ${REPO_URL}",
  "kind": "zone",
  "phase": "http_response_headers_transform",
  "rules": [
    {
      "expression": "true",
      "description": "Secure HTTP Response Headers",
      "action": "rewrite",
      "action_parameters": {
        "headers": {
          "Content-Security-Policy": {
            "operation": "set",
            "value": "${CSP_DEFAULT}"
          },
          "Permissions-Policy": {
            "operation": "set",
            "value": "${PP_DEFAULT}"
          },
          "X-XSS-Protection": {
            "operation": "set",
            "value": "0"
          },
          "X-Frame-Options": {
            "operation": "set",
            "value": "DENY"
          },
          "X-Content-Type-Options": {
            "operation": "set",
            "value": "nosniff"
          },
          "Referrer-Policy": {
            "operation": "set",
            "value": "no-referrer"
          },
          "Cross-Origin-Embedder-Policy": {
            "operation": "set",
            "value": "require-corp; report-to=\"default\";"
          },
          "Cross-Origin-Opener-Policy": {
            "operation": "set",
            "value": "same-origin; report-to=\"default\";"
          },
          "Cross-Origin-Resource-Policy": {
            "operation": "set",
            "value": "same-origin"
          },
          "X-Permitted-Cross-Domain-Policies": {
            "operation": "set",
            "value": "none"
          },
          "Public-Key-Pins": {
            "operation": "remove"
          },
          "X-Powered-By": {
            "operation": "remove"
          },
          "X-AspNet-Version": {
            "operation": "remove"
          }
        }
      }
    },
    {
      "expression": "${EXPRESSION_CMS}",
      "description": "Secure HTTP Response Headers for edit-cms",
      "action": "rewrite",
      "action_parameters": {
        "headers": {
          "Content-Security-Policy": {
            "operation": "set",
            "value": "${CSP_CMS}"
          }
        }
      }
    }
  ]
}
EOF
)"
JSON_REQUEST_UPDATE="$(jq -cn '{ rules: inputs.rules }' <<<"${JSON_REQUEST_FULL}")"
JSON_REQUEST_CREATE="$(jq -c <<<"${JSON_REQUEST_FULL}")"

API_LIST_RULESETS="$(curl -s https://api.cloudflare.com/client/v4/zones/"${CLOUDFLARE_ZONE_ID}"/rulesets -X GET -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}")"
if ! jq -e ".success" <<<"${API_LIST_RULESETS}" >/dev/null 2>&1; then
    echo "ERROR: Cloudflare API Request unsuccessful."
    exit 1
fi

RULESET_ID="$(jq -r '.result[] | select(.phase == "http_response_headers_transform") | .id' <<<"${API_LIST_RULESETS}")"
if [[ -n "${RULESET_ID}" ]]; then
    curl -s https://api.cloudflare.com/client/v4/zones/"${CLOUDFLARE_ZONE_ID}"/rulesets/"${RULESET_ID}" -X PUT -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" --json "${JSON_REQUEST_UPDATE}" | jq -e ".success" >/dev/null 2>&1
else
    curl -s https://api.cloudflare.com/client/v4/zones/"${CLOUDFLARE_ZONE_ID}"/rulesets -X POST -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" --json "${JSON_REQUEST_CREATE}" | jq -e ".success" >/dev/null 2>&1
fi
