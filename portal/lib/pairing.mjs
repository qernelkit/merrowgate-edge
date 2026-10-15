// Pairing a new scanner or label printer. The portal shows a QR code holding its identity and a one-time
// key; the device answers with its own one-time key, and both ends arrive at the same shared secret, which
// goes into the vault for that device. The identity signature lets the device check that it paired with
// this gateway and not with whatever else answered on the depot network.
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const OFFER_TTL_MS = 5 * 60 * 1000;
const offers = new Map();

const spki = (key) => key.export({ type: 'spki', format: 'der' }).toString('base64url');

export function loadIdentity(path) {
  if (existsSync(path)) return createPrivateKey(readFileSync(path));
  const identity = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(path, identity.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  return identity;
}

export function createOffer(identity, depot, now = Date.now()) {
  for (const [id, offer] of offers) {
    if (offer.expires < now) offers.delete(id);
  }
  const oneTime = generateKeyPairSync('x25519');
  const offer = {
    id: randomUUID(),
    depot,
    expires: now + OFFER_TTL_MS,
    identity: spki(createPublicKey(identity)),
    key: spki(oneTime.publicKey),
  };
  offers.set(offer.id, { ...offer, own: oneTime.privateKey });
  return offer;
}

export function acceptDevice(identity, offerId, deviceKey, now = Date.now()) {
  const offer = offers.get(offerId);
  offers.delete(offerId);
  if (!offer || offer.expires < now || typeof deviceKey !== 'string') return null;
  const peer = createPublicKey({ key: Buffer.from(deviceKey, 'base64url'), format: 'der', type: 'spki' });
  const shared = diffieHellman({ privateKey: offer.own, publicKey: peer });
  const transcript = Buffer.from(`${offer.id}.${offer.key}.${deviceKey}`);
  return {
    depot: offer.depot,
    shared,
    confirmation: sign(null, transcript, identity).toString('base64url'),
  };
}
