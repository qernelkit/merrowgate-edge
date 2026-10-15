// Per-device secrets (pairing secrets, Wi-Fi profiles pushed to scanners) are stored sealed. Each device
// has its own key, derived from the portal's master key and the device id, so one leaked record says
// nothing about the others.
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';

const VAULT_CIPHER = 'aes-256-gcm';
const FORMAT = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + IV_BYTES + TAG_BYTES;

function deviceKey(master, deviceId) {
  return Buffer.from(hkdfSync('sha512', master, deviceId, 'merrowgate-device-secret', 32));
}

export function sealSecret(master, deviceId, plaintext) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(VAULT_CIPHER, deviceKey(master, deviceId), iv);
  cipher.setAAD(Buffer.from(deviceId));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([FORMAT]), iv, cipher.getAuthTag(), body]).toString('base64');
}

export function openSecret(master, deviceId, sealed) {
  const raw = Buffer.from(sealed, 'base64');
  if (raw.length < HEADER_BYTES || raw[0] !== FORMAT) throw new Error('sealed record has an unknown format');
  const iv = raw.subarray(1, 1 + IV_BYTES);
  const decipher = createDecipheriv(VAULT_CIPHER, deviceKey(master, deviceId), iv);
  decipher.setAuthTag(raw.subarray(1 + IV_BYTES, HEADER_BYTES));
  decipher.setAAD(Buffer.from(deviceId));
  return Buffer.concat([decipher.update(raw.subarray(HEADER_BYTES)), decipher.final()]);
}

export class Vault {
  constructor(path, master) {
    this.path = path;
    this.master = master;
    this.records = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {};
  }

  put(deviceId, name, value) {
    this.records[deviceId] = { ...this.records[deviceId], [name]: sealSecret(this.master, deviceId, value) };
    this.save();
  }

  get(deviceId, name) {
    const sealed = this.records[deviceId]?.[name];
    return sealed ? openSecret(this.master, deviceId, sealed) : null;
  }

  forget(deviceId) {
    delete this.records[deviceId];
    this.save();
  }

  save() {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.records, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}
