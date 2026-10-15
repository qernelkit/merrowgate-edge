// Carrier partners call back with delivery events (collected, out for delivery, delivered, refused).
// Each partner signs the raw request body with its RSA key; we keep the public halves, one PEM file per
// partner, under /etc/merrowgate/partners (provisioned by the fleet team, not part of the image).
import { constants, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PARTNER_DIR = process.env.PARTNER_KEY_DIR ?? '/etc/merrowgate/partners';
const PARTNER_ID = /^[a-z0-9][a-z0-9-]{1,31}$/;
const EVENT_TYPES = new Set(['collected', 'out-for-delivery', 'delivered', 'refused']);
const loaded = new Map();

function partnerKey(partnerId) {
  if (!PARTNER_ID.test(partnerId)) return null;
  if (!loaded.has(partnerId)) {
    try {
      loaded.set(partnerId, createPublicKey(readFileSync(join(PARTNER_DIR, `${partnerId}.pem`))));
    } catch {
      return null;
    }
  }
  return loaded.get(partnerId);
}

export function verifyCallback(partnerId, body, signatureHeader, logger) {
  const key = partnerKey(partnerId);
  if (!key) {
    logger.warn('callback from an unknown partner', { partner: partnerId });
    return false;
  }
  if (!signatureHeader) {
    logger.warn('partner callback without a signature header', { partner: partnerId });
    return false;
  }
  return verify('sha256', body, {
    key,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  }, Buffer.from(signatureHeader, 'base64'));
}

export function parseEvent(body) {
  const event = JSON.parse(body.toString('utf8'));
  if (!EVENT_TYPES.has(event.type)) throw new RangeError(`unknown event type: ${event.type}`);
  if (typeof event.consignment !== 'string' || event.consignment.length === 0) {
    throw new RangeError('event has no consignment number');
  }
  return { type: event.type, consignment: event.consignment, at: event.at ?? new Date().toISOString() };
}
