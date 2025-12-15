#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[*] $*" >&2
}

URL="${1:-}"

if [[ -z "$URL" || "$URL" != oktaverify://* ]]; then
  echo "Usage: $0 'oktaverify://...'" >&2
  exit 1
fi

log "Parsing oktaverify URL"

OTDT="$(echo "$URL" | sed -n 's/.*[?&]t=\([^&]*\).*/\1/p')"
AUTH_ID="$(echo "$URL" | sed -n 's/.*[?&]f=\([^&]*\).*/\1/p')"
BASE_URL="$(echo "$URL" | sed -n 's/.*[?&]s=\(https:\/\/[^&]*okta\.com\).*/\1/p')"

if [[ -z "$OTDT" || -z "$AUTH_ID" || -z "$BASE_URL" ]]; then
  echo "Failed to parse required parameters (t, f, s)" >&2
  exit 1
fi

log "OTDT acquired"
log "Authenticator ID acquired"
log "Okta base URL: $BASE_URL"

log "Fetching OAuth public keys"
KEY_JSON="$(curl -s "${BASE_URL}/oauth2/v1/keys")"

KID="$(echo "$KEY_JSON" | jq -r '.keys[0].kid')"
N="$(echo "$KEY_JSON" | jq -r '.keys[0].n')"

if [[ -z "$KID" || -z "$N" ]]; then
  echo "Failed to extract key material" >&2
  exit 1
fi

log "Using key kid=$KID"

log "Building authenticator registration payload"

BODY="$(jq -n \
  --arg authId "$AUTH_ID" \
  --arg kid "$KID" \
  --arg n "$N" \
  '{
    authenticatorId: $authId,
    device: {
      clientInstanceBundleId: "com.okta.android.auth",
      clientInstanceDeviceSdkVersion: "DeviceSDK 0.19.0",
      clientInstanceVersion: "6.8.1",
      clientInstanceKey: {
        alg: "RS256",
        e: "AQAB",
        "okta:isFipsCompliant": false,
        "okta:kpr": "SOFTWARE",
        kty: "RSA",
        use: "sig",
        kid: $kid,
        n: $n
      },
      deviceAttestation: {},
      displayName: "KeePassXC",
      fullDiskEncryption: false,
      isHardwareProtectionEnabled: false,
      manufacturer: "unknown",
      model: "Google",
      osVersion: "25",
      platform: "ANDROID",
      rootPrivileges: true,
      screenLock: false,
      secureHardwarePresent: false
    },
    key: "okta_verify",
    methods: [
      {
        isFipsCompliant: false,
        supportUserVerification: false,
        type: "totp"
      }
    ]
  }')"


log "Registering new authenticator with Okta"
RESP="$(curl -s -X POST "${BASE_URL}/idp/authenticators" \
  -H "Authorization: OTDT ${OTDT}" \
  -H "Content-Type: application/json" \
  --data "$BODY")"

SECRET="$(echo "$RESP" | jq -r '.methods[0].sharedSecret // empty')"

if [[ -z "$SECRET" ]]; then
  echo "Failed to obtain sharedSecret" >&2
  echo "$RESP" | jq . >&2
  exit 1
fi

log "sharedSecret successfully obtained"
log "You can now register this secret in KeePass (TOTP)"

echo "$SECRET"