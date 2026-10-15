// Device registry: every scanner, label printer and sensor gateway paired with this depot's gateway.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import * as zlib from 'node:zlib';

export const DEVICE_KINDS = ['scanner', 'label-printer', 'sensor-gateway'];
const SERIAL_FORMAT = /^[A-Z0-9][A-Z0-9-]{5,31}$/;

// Short id for asset stickers and the dashboard, and a tile colour that stays put between visits.
export function displayFields(serial) {
  const shortId = createHash('sha1').update(serial).digest('hex').slice(0, 12);
  const tile = zlib.crc32(serial) % 64;
  return { shortId, tile };
}

function compareBy(keys) {
  return (a, b) => {
    for (const k of keys) {
      const x = String(a[k] ?? '');
      const y = String(b[k] ?? '');
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  };
}

export class DeviceRegistry {
  constructor(path, sortOrder = ['depot', 'bay', 'serial']) {
    this.path = path;
    this.sortOrder = sortOrder;
    this.devices = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : [];
  }

  list() {
    return [...this.devices].sort(compareBy(this.sortOrder));
  }

  find(serial) {
    return this.devices.find((d) => d.serial === serial) ?? null;
  }

  add(device) {
    const serial = String(device.serial ?? '').toUpperCase();
    if (!SERIAL_FORMAT.test(serial)) throw new RangeError(`not a device serial: ${device.serial}`);
    if (!DEVICE_KINDS.includes(device.kind)) throw new RangeError(`unknown device kind: ${device.kind}`);
    const existing = this.find(serial);
    const record = { ...existing, ...device, serial, ...displayFields(serial), updated: new Date().toISOString() };
    this.devices = this.devices.filter((d) => d.serial !== serial).concat(record);
    this.save();
    return record;
  }

  addMany(devices) {
    let added = 0;
    const skipped = [];
    for (const device of devices) {
      try {
        this.add(device);
        added += 1;
      } catch (err) {
        skipped.push({ serial: device.serial, reason: err.message });
      }
    }
    return { added, skipped };
  }

  remove(serial) {
    const before = this.devices.length;
    this.devices = this.devices.filter((d) => d.serial !== serial);
    if (this.devices.length !== before) this.save();
    return this.devices.length !== before;
  }

  save() {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.devices, null, 2));
    renameSync(tmp, this.path);
  }
}
