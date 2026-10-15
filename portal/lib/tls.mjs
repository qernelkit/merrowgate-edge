// Listener settings for the portal. nginx proxies /portal/ to it over loopback; the same settings
// apply when the portal runs on its own on a laptop (see scripts/gen-dev-certs.sh).
import { readFileSync } from 'node:fs';

const PKI_DIR = process.env.MERROWGATE_PKI_DIR ?? '/etc/merrowgate/pki';

export const defaultPaths = {
  cert: process.env.PORTAL_CERT ?? `${PKI_DIR}/portal/portal.crt`,
  key: process.env.PORTAL_KEY ?? `${PKI_DIR}/portal/portal.key`,
  chain: process.env.PORTAL_CHAIN ?? `${PKI_DIR}/portal/chain.pem`,
};

function readOptional(path) {
  return path ? readFileSync(path, 'utf8') : '';
}

/** @returns {import('node:https').ServerOptions} */
export function serverOptions(paths = defaultPaths) {
  return {
    // leaf first, then the issuing CA, so devices that only carry the root can build the path
    cert: readFileSync(paths.cert, 'utf8') + readOptional(paths.chain),
    key: readFileSync(paths.key),
    minVersion: 'TLSv1.2',
    ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305',
    ecdhCurve: 'X25519:P-256',
    honorCipherOrder: true,
    sessionTimeout: 300,
  };
}
