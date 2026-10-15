#!/bin/sh
# Container entrypoint, run under tini. Prepares runtime state on the /var/lib/merrowgate volume, starts
# the depot-facing services and keeps edgectl in the foreground: when edgectl exits, the container stops.
set -eu

STATE_DIR=${STATE_DIR:-/var/lib/merrowgate}
RUN_DIR=/run/merrowgate

log() {
	printf '%s entrypoint: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

mkdir -p "$STATE_DIR/portal" "$STATE_DIR/firmware" "$RUN_DIR/nginx" /run/nginx /var/lib/mosquitto
chmod 0700 "$STATE_DIR"
chown mosquitto:mosquitto /var/lib/mosquitto

# Audit log exports leave the gateway signed with a key of its own, made on first start and kept on the volume.
echo "edge gateway $(cat /etc/merrowgate/build-sha)"
if [ ! -s "$STATE_DIR/audit-signing.key" ]; then
	log "first start on this volume: creating the audit signing key"
	openssl genpkey -algorithm ed25519 -out "$STATE_DIR/audit-signing.key"
	chmod 0600 "$STATE_DIR/audit-signing.key"
fi

# nginx includes this file in http.d/edge.conf; without it, firmware downloads answer 503.
if [ -n "${FIRMWARE_LINK_SECRET:-}" ]; then
	case $FIRMWARE_LINK_SECRET in
		*[!A-Za-z0-9_-]*)
			log "FIRMWARE_LINK_SECRET may only hold letters, digits, '-' and '_'"
			exit 64
			;;
	esac
	umask 027
	printf 'set $firmware_link_secret "%s";\n' "$FIRMWARE_LINK_SECRET" > "$RUN_DIR/nginx/firmware-link.conf"
	umask 022
else
	log "FIRMWARE_LINK_SECRET is not set; firmware downloads are switched off"
fi

log "starting crond, sshd, mosquitto, nginx and the device portal"
crond -f -l 8 &
/usr/sbin/sshd -D -e &
mosquitto -c /etc/mosquitto/mosquitto.conf &
nginx -g 'daemon off;' &
node /opt/portal/server.mjs &

exec /usr/local/bin/edgectl -config /etc/merrowgate/gateway.yaml serve
