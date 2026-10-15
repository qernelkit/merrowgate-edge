// Imports the device lists that v1 portals (before the gateway) exported when a depot was migrated.
// An export is "MGX1", a 16-byte salt, a 16-byte IV, then the JSON device list encrypted under a key
// derived from the passphrase the depot manager chose at export time.
import { createDecipheriv, pbkdf2Sync } from 'node:crypto';

const MAGIC = 'MGX1';
const SALT_BYTES = 16;
const IV_BYTES = 16;
const BODY_OFFSET = MAGIC.length + SALT_BYTES + IV_BYTES;

export class ImportError extends Error {}

export function readV1Export(file, passphrase) {
  if (file.length <= BODY_OFFSET || file.toString('latin1', 0, MAGIC.length) !== MAGIC) {
    throw new ImportError('not a v1 portal export');
  }
  const salt = file.subarray(MAGIC.length, MAGIC.length + SALT_BYTES);
  const iv = file.subarray(MAGIC.length + SALT_BYTES, BODY_OFFSET);
  const key = pbkdf2Sync(passphrase, salt, 100000, 16, 'sha256');
  const decipher = createDecipheriv('aes-128-cbc', key, iv);
  let json;
  try {
    json = Buffer.concat([decipher.update(file.subarray(BODY_OFFSET)), decipher.final()]).toString('utf8');
  } catch {
    throw new ImportError('the export could not be opened with that passphrase');
  }
  return normalise(JSON.parse(json));
}

// v1 used its own field names and upper-case kinds.
const KINDS = { SCANNER: 'scanner', PRINTER: 'label-printer', SENSOR_GW: 'sensor-gateway' };

function normalise(doc) {
  const rows = Array.isArray(doc?.devices) ? doc.devices : [];
  return rows
    .filter((row) => typeof row.serial_no === 'string' && row.serial_no.length > 0)
    .map((row) => ({
      serial: row.serial_no.trim().toUpperCase(),
      kind: KINDS[row.type] ?? 'scanner',
      model: row.model ?? 'unknown',
      depot: row.depot_code ?? doc.depot ?? null,
      bay: row.location ?? null,
      importedFrom: 'v1',
    }));
}
