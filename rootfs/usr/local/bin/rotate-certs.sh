#!/bin/sh
# Renews the portal certificate (nginx on 443 and 8443, mosquitto on 8883, the portal itself) through the
# Merrowgate issuing service once it is within 30 days of expiry. Runs daily from
# /etc/periodic/daily/rotate-portal-cert; "rotate-certs.sh --force" renews whatever the expiry.
#
# The issuing service answers with a tar holding bundle.tar (the new certificate and chain.pem) and
# bundle.tar.sig, a detached signature over it by the rotation signer. Enrolment installs the signer's
# public key next to the portal certificate.
set -eu

PKI=/etc/merrowgate/pki
ISSUER_URL=${ISSUER_URL:-https://pki.merrowgate.example/v1/portal/renew}
RENEW_BEFORE=2592000

log() {
	logger -t rotate-certs "$*" 2>/dev/null || true
	echo "rotate-certs: $*"
}

if [ ! -r "$PKI/rotation-signer.pub" ]; then
	log "gateway not enrolled yet (no rotation signer); nothing to do"
	exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ "${1:-}" != "--force" ] && openssl x509 -noout -checkend "$RENEW_BEFORE" -in "$PKI/portal/portal.crt" >/dev/null; then
	log "portal certificate valid for more than 30 days; rotation skipped"
	exit 0
fi
openssl req -new \
	-newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	-sha256 \
	-nodes -keyout "$work/portal.key" \
	-subj "/C=GB/O=Merrowgate Systems/CN=portal.merrowgate.example" \
	-addext "subjectAltName=DNS:portal.merrowgate.example,DNS:edge.merrowgate.example" \
	-out "$work/request.pem"

log "requesting a new portal certificate from $ISSUER_URL"
wget -q -T 30 --header 'Content-Type: application/x-pem-file' --post-file "$work/request.pem" \
	-O "$work/response.tar" "$ISSUER_URL"
tar -xf "$work/response.tar" -C "$work" bundle.tar bundle.tar.sig

bundle="$work/bundle.tar"
if ! openssl dgst -sha256 -verify "$PKI/rotation-signer.pub" -signature "$bundle.sig" "$bundle" >/dev/null; then
	log "bundle signature did not verify; keeping the current certificate"
	exit 1
fi
tar -xf "$bundle" -C "$work" portal.crt chain.pem

if [ "$(openssl x509 -noout -pubkey -in "$work/portal.crt")" != "$(openssl pkey -pubout -in "$work/portal.key")" ]; then
	log "issued certificate does not match the new key; keeping the current certificate"
	exit 1
fi

install -m 0644 "$work/chain.pem" "$PKI/portal/chain.pem"
install -m 0644 "$work/portal.crt" "$PKI/portal/portal.crt"
install -m 0640 -g mosquitto "$work/portal.key" "$PKI/portal/portal.key"
nginx -s reload
log "new portal certificate installed; nginx reloaded, mosquitto and the portal pick it up on their next restart"
