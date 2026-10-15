#!/usr/bin/env bash
# Makes a 30-day self-signed certificate for running the device portal on a laptop, outside the image:
#
#   scripts/gen-dev-certs.sh
#   PORTAL_CERT=certs/dev/localhost.crt PORTAL_KEY=certs/dev/localhost.key PORTAL_CHAIN= \
#     PORTAL_STATE_DIR=/tmp/portal-state node portal/server.mjs
#
# Browsers will warn about it; that is expected. Nothing under certs/dev/ goes into the image.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
out=certs/dev
mkdir -p "$out"

if [[ -f "$out/localhost.crt" && "${1:-}" != "--force" ]] \
  && openssl x509 -noout -checkend 86400 -in "$out/localhost.crt" >/dev/null; then
  echo "$out/localhost.crt is still valid; pass --force to replace it"
  exit 0
fi

openssl req -x509 \
  -newkey rsa:2048 \
  -sha256 -days 30 -nodes \
  -keyout "$out/localhost.key" -out "$out/localhost.crt" \
  -subj "/C=GB/O=Merrowgate Systems Development/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -addext "extendedKeyUsage=serverAuth"
chmod 0600 "$out/localhost.key"
echo "wrote $out/localhost.crt and $out/localhost.key"
