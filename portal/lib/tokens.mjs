// Devices call the portal API with the bearer token edgectl gave them at enrolment, signed with the
// gateway's token-signing key. The portal only checks tokens; it never issues them.
import { subtle } from 'node:crypto';

// Public half of /etc/merrowgate/pki/token-signing.key, as edgectl publishes it in its key set.
const TOKEN_SIGNING_JWK = {
  "kty": "EC",
  "crv": "P-256",
  "x": "tTi0NX2Cl0YHumfFFELbfFjEs59q5X5DcoNW4_cAMcg",
  "y": "59G0VZLQeDEgm4uhlCNV0VkhdL7AtyYYMzS1flQvDI8",
};

let cachedKey;

function tokenKey() {
  cachedKey ??= subtle.importKey('jwk', TOKEN_SIGNING_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return cachedKey;
}

const decodePart = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

// The header is not consulted: the key and the algorithm are fixed above, so a token cannot pick them.
export async function verifyDeviceToken(token, now = Date.now()) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const signed = new TextEncoder().encode(`${header}.${payload}`);
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await tokenKey(), Buffer.from(signature, 'base64url'), signed);
  if (!ok) return null;
  let claims;
  try {
    claims = decodePart(payload);
  } catch {
    return null;
  }
  if (typeof claims.sub !== 'string' || typeof claims.exp !== 'number') return null;
  if (claims.exp * 1000 <= now) return null;
  return { deviceId: claims.sub, depot: claims.depot ?? null, scope: Array.isArray(claims.scope) ? claims.scope : [] };
}

export function bearer(req) {
  const value = req.headers.authorization ?? '';
  return value.startsWith('Bearer ') ? value.slice(7).trim() : null;
}
