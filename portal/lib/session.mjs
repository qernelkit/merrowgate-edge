// Signed session cookies for depot staff. The cookie carries the claims as base64url JSON and a MAC
// over them: nothing in it is secret, it only has to be unforgeable.
import { createHmac, timingSafeEqual } from 'node:crypto';

export const COOKIE_NAME = 'mg_portal';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // one depot shift

const mac = (body, secret) => createHmac('sha256', secret).update(body).digest('base64url');

export function issueSession(claims, secret, now = Date.now()) {
  const body = Buffer.from(JSON.stringify({ ...claims, exp: now + SESSION_TTL_MS })).toString('base64url');
  return `${body}.${mac(body, secret)}`;
}

export function readSession(value, secret, now = Date.now()) {
  if (typeof value !== 'string') return null;
  const dot = value.lastIndexOf('.');
  if (dot <= 0) return null;
  const body = value.slice(0, dot);
  const given = Buffer.from(value.slice(dot + 1));
  const expected = Buffer.from(mac(body, secret));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  let claims;
  try {
    claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (typeof claims.exp !== 'number' || claims.exp < now) return null;
  return claims;
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

export function sessionCookie(value) {
  const maxAge = value ? SESSION_TTL_MS / 1000 : 0;
  return `${COOKIE_NAME}=${value}; Path=/portal; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
