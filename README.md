# Merrowgate edge gateway

The container that runs in every Merrowgate depot. It sits between the depot floor and the Merrowgate
cloud and does five jobs:

- **TLS for depot devices.** nginx terminates TLS for scanners, label printers and sensor gateways on 443,
  with a separate listener on 8443 for the 2017-generation handheld scanners.
- **Telemetry.** mosquitto takes MQTT from devices with certificates (8883) and from sensor gateways that
  use a pre-shared key (8884). `edgectl` relays readings to the yard system and the cloud.
- **Bastion.** OpenSSH on 2222 lets field engineers reach depot devices with short-lived certificates.
- **Control API.** `edgectl` (Go) issues device tokens, enrols devices, checks firmware manifests, sends
  webhooks and keeps the audit log.
- **Device portal.** A small Node.js app where depot staff pair devices, find them, import device lists
  from v1 portals and move shipments along.

One image is built for `linux/amd64` (depot servers) and `linux/arm64` (the fanless boxes in the smaller
depots).

## Repository layout

| Path | What it is |
|---|---|
| `cmd/edgectl`, `internal/` | the control API, one package per concern (`tokens`, `enrol`, `firmware`, `mqtt`, …) |
| `portal/` | the device portal; plain ES modules on Node 22, no dependencies |
| `rootfs/` | copied over `/` in the image: nginx, OpenSSH and mosquitto settings, `gateway.yaml`, the entrypoint and maintenance scripts |
| `certs/` | the internal CA certificates, the portal certificate and key, and the token and firmware keys the gateway needs; copied to `/etc/merrowgate/pki/` |
| `certs/dev/` | a certificate for running the portal on a laptop (`scripts/gen-dev-certs.sh`); never in the image |
| `deploy/k8s/` | manifests for depots that run the gateway on their single-node cluster |
| `.github/workflows/` | the release pipeline: test, build both platforms, push, sign |

## Building

```sh
mkdir -p secrets && echo 'a password for /ops/' > secrets/fieldops.txt
docker buildx build --platform linux/amd64,linux/arm64 \
  --secret id=fieldops_password,src=secrets/fieldops.txt \
  --build-arg MQTT_RELAY_PASSWORD="$MQTT_RELAY_PASSWORD" \
  --build-arg GIT_SHA="$(git rev-parse HEAD)" \
  -t merrowgate/edge-gateway:dev .
```

A plain `docker build .` works too; without the secret and the build argument the image gets placeholder
passwords for `/ops/` and the broker account, which is fine on a workstation and wrong anywhere else. The
Go code is cross-compiled in the build stage, so an arm64 image builds quickly on an amd64 machine. The
`node` binary comes from the official `node:22-alpine` image rather than from Alpine's packages.

Base images are pinned by digest. Bump them deliberately, in their own commit.

## Running locally

```sh
echo 'any long random string' > secrets/webhook.txt
export MQTT_RELAY_PASSWORD='the broker password edgectl uses'
docker compose up --build
```

| Port | Service |
|---|---|
| 443 | nginx: control API (`/api/`), portal (`/portal/`), field operations (`/ops/`), firmware (`/firmware/`) |
| 8443 | nginx: handheld scanners from 2017 |
| 8883 | mosquitto, client certificates from the device CA |
| 8884 | mosquitto, pre-shared keys (sensor gateways) |
| 2222 | sshd, engineer certificates only |

State (the gateway's master secret, sealed accounts, the device registry, the audit log) lives on the
`/var/lib/merrowgate` volume. Losing the volume means re-enrolling the gateway.

`FIRMWARE_LINK_SECRET` switches on firmware downloads; it must match the fleet console that mints the
download links.

## Configuration

- `rootfs/etc/merrowgate/gateway.yaml`: depot identity, listeners, token lifetime, admin password
  settings, webhooks, telemetry.
- `rootfs/etc/nginx/`: `nginx.conf` holds the TLS policy for every listener; `http.d/` holds the sites.
- `rootfs/etc/ssh/sshd_config`: the bastion. Engineers' certificates must be signed by the CA in
  `rootfs/etc/ssh/engineer_ca.pub` and carry the principal `fieldops`.
- `rootfs/etc/mosquitto/`: broker settings, the ACL, and `psk.txt` (one line per sensor gateway,
  `identity:key`).

The portal certificate is renewed by `rotate-certs.sh`, which `crond` runs daily and which asks the
Merrowgate issuing service for a new certificate once the current one has less than 30 days left.

## Development

```sh
go vet ./... && go test ./...
cd portal && npm test
```

To run the portal outside the image, make a local certificate with `scripts/gen-dev-certs.sh` and follow
the instructions at the top of that script.

## Releasing

Push a tag `vX.Y.Z`. The release workflow runs the tests, builds and pushes both platforms to
`registry.merrowgate.example/edge/gateway`, and signs the pushed digest with the workflow's identity.
Depot nodes refuse images whose signature does not verify.
