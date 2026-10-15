// Depot staff sign in with their badge number and a six-digit PIN. PINs are kept as scrypt hashes in
// the portal's state directory; the PIN itself never touches disk.
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';

const PIN_FORMAT = /^\d{6}$/;
const BADGE_FORMAT = /^[A-Z]{2}\d{4,6}$/;

function derive(pin, salt) {
  return scryptSync(pin, salt, 32, { N: 16384, r: 8, p: 1 });
}

export function hashPin(pin) {
  if (!PIN_FORMAT.test(pin)) throw new RangeError('a PIN is six digits');
  const salt = randomBytes(16);
  return `${salt.toString('base64')}:${derive(pin, salt).toString('base64')}`;
}

export function checkPin(pin, stored) {
  const [salt, hash] = String(stored ?? '').split(':');
  if (!salt || !hash || !PIN_FORMAT.test(String(pin))) return false;
  const expected = Buffer.from(hash, 'base64');
  const actual = derive(String(pin), Buffer.from(salt, 'base64'));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export class StaffDirectory {
  constructor(path) {
    this.path = path;
    this.staff = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {};
  }

  verify(badge, pin) {
    const entry = this.staff[badge];
    if (!entry || entry.disabled) return null;
    return checkPin(pin, entry.pin) ? { badge, name: entry.name, depot: entry.depot, role: entry.role } : null;
  }

  setPin(badge, pin, details = {}) {
    if (!BADGE_FORMAT.test(badge)) throw new RangeError(`not a badge number: ${badge}`);
    this.staff[badge] = { ...this.staff[badge], ...details, pin: hashPin(pin), changed: new Date().toISOString() };
    this.save();
  }

  disable(badge) {
    if (this.staff[badge]) {
      this.staff[badge].disabled = true;
      this.save();
    }
  }

  save() {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.staff, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}
