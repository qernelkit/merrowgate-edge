# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv
#
# Merrowgate edge gateway: edgectl (Go), the device portal (Node.js), nginx, OpenSSH and mosquitto in one
# image for linux/amd64 and linux/arm64. Build with the field-ops password as a secret:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --secret id=fieldops_password,src=secrets/fieldops.txt --build-arg GIT_SHA="$(git rev-parse HEAD)" .

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/edgectl ./cmd/edgectl

# Only the node binary is taken from here: nodejs from apk would pull in ca-certificates and rebuild the
# system trust store.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS node

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache nginx openssh mosquitto openssl tini libstdc++ libgcc \
 && adduser -D -h /home/fieldops -s /bin/sh fieldops \
 && sed -i 's/^fieldops:!/fieldops:*/' /etc/shadow
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=build /out/edgectl /usr/local/bin/edgectl
COPY rootfs/ /
COPY certs/ /etc/merrowgate/pki/
COPY portal/ /opt/portal/

# Trust the Merrowgate root for outbound calls (edgectl to the cloud, rotate-certs.sh to the issuing service).
RUN mkdir -p /usr/local/share/ca-certificates \
 && cp /etc/merrowgate/pki/merrowgate-root-ca.crt /usr/local/share/ca-certificates/ \
 && cat /usr/local/share/ca-certificates/merrowgate-root-ca.crt >> /etc/ssl/certs/ca-certificates.crt

# sshd host keys, nginx DH parameters and the certificate for clients that send no known server name.
RUN ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key \
 && ssh-keygen -q -t ecdsa -b 256 -N '' -f /etc/ssh/ssh_host_ecdsa_key \
 && ssh-keygen -q -t rsa -b 3072 -N '' -f /etc/ssh/ssh_host_rsa_key
RUN openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out /etc/nginx/dhparam.pem
RUN openssl req -x509 \
      -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
      -sha256 -days 825 -nodes -subj '/CN=edge.local' \
      -keyout /etc/merrowgate/pki/fallback.key -out /etc/merrowgate/pki/fallback.crt

# Basic auth for /ops/. Release builds pass the password as a secret (.github/workflows/release.yml); a
# local build without it gets a placeholder.
RUN --mount=type=secret,id=fieldops_password,required=false \
    printf 'fieldops:%s\n' "$( { cat /run/secrets/fieldops_password 2>/dev/null || echo change-me-on-first-boot; } | openssl passwd -6 -stdin)" > /etc/nginx/.htpasswd

# mosquitto drops to its own user before it reads its files; the portal key is shared with the 8883 listener.
RUN chown mosquitto:mosquitto /etc/mosquitto/acl /etc/mosquitto/psk.txt && chmod 0600 /etc/mosquitto/acl /etc/mosquitto/psk.txt \
 && chgrp mosquitto /etc/merrowgate/pki/portal/portal.key && chmod 0640 /etc/merrowgate/pki/portal/portal.key
ARG MQTT_RELAY_PASSWORD=change-me-on-first-boot
RUN mosquitto_passwd -b -c /etc/mosquitto/passwd device-relay "$MQTT_RELAY_PASSWORD" \
 && chown mosquitto:mosquitto /etc/mosquitto/passwd

ARG GIT_SHA=dev
LABEL org.opencontainers.image.revision=$GIT_SHA
RUN echo "$GIT_SHA" > /etc/merrowgate/build-sha

EXPOSE 443 8443 8883 8884 2222
VOLUME ["/var/lib/merrowgate"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s CMD ["/usr/local/bin/healthcheck.sh"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
