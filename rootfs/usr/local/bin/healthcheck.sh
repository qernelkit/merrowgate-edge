#!/bin/sh
# Docker HEALTHCHECK: edgectl answers on its local health endpoint, and the depot-facing listener on 443
# completes a TLS 1.3 handshake on the hybrid group the newer scanners use.
set -eu

wget -q -T 3 -O- http://127.0.0.1:9000/healthz >/dev/null
openssl s_client -connect 127.0.0.1:443 -servername edge.merrowgate.example -tls1_3 -groups X25519MLKEM768 </dev/null >/dev/null 2>&1
