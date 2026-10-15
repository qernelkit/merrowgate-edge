// Depot device portal. Runs on loopback behind nginx, which forwards /portal/ here; depot staff use it to
// pair devices, look them up, import v1 device lists and move shipments along. Devices themselves call
// /portal/api/device/* with their enrolment token.
import { createServer } from 'node:https';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { serverOptions } from './lib/tls.mjs';
import { COOKIE_NAME, issueSession, parseCookies, readSession, sessionCookie } from './lib/session.mjs';
import { StaffDirectory } from './lib/pin.mjs';
import { Vault } from './lib/vault.mjs';
import { DeviceRegistry } from './lib/devices.mjs';
import { ImportError, readV1Export } from './lib/v1-import.mjs';
import { parseEvent, verifyCallback } from './lib/partner.mjs';
import { bearer, verifyDeviceToken } from './lib/tokens.mjs';
import { acceptDevice, createOffer, loadIdentity } from './lib/pairing.mjs';
import { searchDevices } from './lib/search.mjs';
import { keyringSheet } from './lib/keyring.mjs';
import { eurRate, surchargeEur } from './lib/rates.mjs';
import { applyStatus } from './lib/shipments.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(HERE, 'public');
const STATE_DIR = process.env.PORTAL_STATE_DIR ?? '/var/lib/merrowgate/portal';
const HOST = process.env.PORTAL_HOST ?? '127.0.0.1';
const PORT = Number(process.env.PORTAL_PORT ?? 8444);
const SORT_ORDER = (process.env.PORTAL_SORT_KEYS ?? 'depot,bay,serial').split(',').map((s) => s.trim());
const MAX_BODY = 2 * 1024 * 1024;
const CONTENT_TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

function log(level, msg, fields = {}) {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields })}\n`);
}
const logger = { info: (m, f) => log('info', m, f), warn: (m, f) => log('warn', m, f) };

// Secrets this portal generates for itself on first start; they live on the state volume only.
function stateSecret(name) {
  const path = join(STATE_DIR, name);
  if (!existsSync(path)) writeFileSync(path, randomBytes(32), { mode: 0o600 });
  return readFileSync(path);
}

mkdirSync(STATE_DIR, { recursive: true });
const sessionSecret = stateSecret('session.secret');
const staff = new StaffDirectory(join(STATE_DIR, 'staff.json'));
const vault = new Vault(join(STATE_DIR, 'vault.json'), stateSecret('vault.master'));
const registry = new DeviceRegistry(join(STATE_DIR, 'devices.json'), SORT_ORDER);
const identity = loadIdentity(join(STATE_DIR, 'portal-identity.pem'));
const shipmentsPath = join(STATE_DIR, 'shipments.json');
const vansPath = join(STATE_DIR, 'vans.json');
const shipments = existsSync(shipmentsPath) ? JSON.parse(readFileSync(shipmentsPath, 'utf8')) : {};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, body, headers = {}) {
  const json = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new HttpError(413, 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const readJson = async (req) => {
  try {
    return JSON.parse((await readBody(req)).toString('utf8') || '{}');
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(400, 'body is not JSON');
  }
};

function staffSession(req) {
  const claims = readSession(parseCookies(req.headers.cookie)[COOKIE_NAME], sessionSecret);
  if (!claims) throw new HttpError(401, 'sign in first');
  return claims;
}

function saveShipments() {
  writeFileSync(`${shipmentsPath}.tmp`, JSON.stringify(shipments, null, 2));
  renameSync(`${shipmentsPath}.tmp`, shipmentsPath);
}

async function handle(req, res, url) {
  const path = url.pathname.replace(/^\/portal/, '') || '/';

  if (req.method === 'GET' && (path === '/' || path === '/app.js')) {
    const file = path === '/' ? 'index.html' : 'app.js';
    return send(res, 200, readFileSync(join(PUBLIC_DIR, file)), { 'content-type': CONTENT_TYPES[extname(file)] });
  }

  if (req.method === 'POST' && path === '/api/login') {
    const { badge, pin } = await readJson(req);
    const who = staff.verify(String(badge ?? ''), String(pin ?? ''));
    if (!who) {
      logger.warn('failed sign-in', { badge });
      throw new HttpError(401, 'badge or PIN not recognised');
    }
    logger.info('signed in', { badge: who.badge, depot: who.depot });
    return send(res, 200, { name: who.name, depot: who.depot }, { 'set-cookie': sessionCookie(issueSession(who, sessionSecret)) });
  }

  if (req.method === 'POST' && path === '/api/logout') {
    return send(res, 204, '', { 'set-cookie': sessionCookie('') });
  }

  if (req.method === 'GET' && path === '/api/devices') {
    staffSession(req);
    return send(res, 200, searchDevices(registry.list(), url.searchParams.get('q')));
  }

  if (req.method === 'POST' && path === '/api/pair') {
    const who = staffSession(req);
    return send(res, 201, createOffer(identity, who.depot));
  }

  const offer = path.match(/^\/api\/pair\/([0-9a-f-]{36})\/complete$/);
  if (req.method === 'POST' && offer) {
    const who = staffSession(req);
    const { deviceKey, serial, kind, model, bay } = await readJson(req);
    const result = acceptDevice(identity, offer[1], deviceKey);
    if (!result) throw new HttpError(410, 'offer expired or unknown; start again from the dashboard');
    const device = registry.add({ serial, kind, model, bay, depot: result.depot, pairedBy: who.badge });
    vault.put(device.serial, 'link', result.shared);
    logger.info('device paired', { serial: device.serial, depot: device.depot, by: who.badge });
    return send(res, 201, { serial: device.serial, shortId: device.shortId, confirmation: result.confirmation });
  }

  if (req.method === 'POST' && path === '/api/import') {
    const who = staffSession(req);
    const passphrase = req.headers['x-export-passphrase'];
    if (typeof passphrase !== 'string' || passphrase.length === 0) throw new HttpError(400, 'export passphrase missing');
    let devices;
    try {
      devices = readV1Export(await readBody(req), passphrase);
    } catch (err) {
      if (err instanceof ImportError) throw new HttpError(422, err.message);
      throw err;
    }
    const outcome = registry.addMany(devices.map((d) => ({ ...d, depot: d.depot ?? who.depot })));
    logger.info('v1 import', { depot: who.depot, added: outcome.added, skipped: outcome.skipped.length });
    return send(res, 200, outcome);
  }

  const callback = path.match(/^\/api\/partners\/([a-z0-9-]+)\/events$/);
  if (req.method === 'POST' && callback) {
    const body = await readBody(req);
    if (!verifyCallback(callback[1], body, req.headers['x-partner-signature'], logger)) {
      throw new HttpError(403, 'callback rejected');
    }
    const event = parseEvent(body);
    const shipment = shipments[event.consignment];
    if (shipment) {
      shipment.partnerEvents = [...(shipment.partnerEvents ?? []), { partner: callback[1], ...event }];
      saveShipments();
    }
    return send(res, 202, { accepted: true });
  }

  const status = path.match(/^\/api\/shipments\/([A-Z0-9-]+)\/status$/);
  if (req.method === 'POST' && status) {
    const who = staffSession(req);
    const shipment = shipments[status[1]];
    if (!shipment) throw new HttpError(404, 'no such shipment');
    const { to, sealNumber } = await readJson(req);
    try {
      shipments[status[1]] = applyStatus(shipment, to, who.badge, sealNumber);
    } catch (err) {
      throw new HttpError(409, err.message);
    }
    saveShipments();
    return send(res, 200, shipments[status[1]]);
  }

  if (req.method === 'GET' && path === '/api/surcharge') {
    staffSession(req);
    const fuel = Number(url.searchParams.get('fuel_gbp'));
    if (!Number.isFinite(fuel) || fuel < 0) throw new HttpError(400, 'fuel_gbp must be a positive amount');
    return send(res, 200, { eur: surchargeEur(fuel, await eurRate('GBP')) });
  }

  if (req.method === 'GET' && path === '/api/keyring') {
    const who = staffSession(req);
    const vans = existsSync(vansPath) ? JSON.parse(readFileSync(vansPath, 'utf8')) : [];
    return send(res, 200, { labels: keyringSheet(who.depot, vans.filter((v) => v.depot === who.depot)) });
  }

  if (req.method === 'GET' && path === '/api/device/self') {
    const device = await verifyDeviceToken(bearer(req));
    if (!device) throw new HttpError(401, 'device token rejected');
    const record = registry.find(device.deviceId);
    if (!record) throw new HttpError(404, 'device not registered at this depot');
    return send(res, 200, { serial: record.serial, shortId: record.shortId, depot: record.depot, bay: record.bay });
  }

  throw new HttpError(404, 'not found');
}

const server = createServer(serverOptions(), (req, res) => {
  const url = new URL(req.url ?? '/', 'https://portal.invalid');
  handle(req, res, url).catch((err) => {
    const code = err instanceof HttpError ? err.status : 500;
    if (code === 500) log('error', 'request failed', { path: url.pathname, error: String(err?.stack ?? err) });
    if (!res.headersSent) send(res, code, { error: code === 500 ? 'internal error' : err.message });
  });
});

server.listen(PORT, HOST, () => logger.info('portal listening', { host: HOST, port: PORT }));

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
