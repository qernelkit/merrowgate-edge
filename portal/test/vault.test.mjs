import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openSecret, sealSecret, Vault } from '../lib/vault.mjs';

const hashOf = (buf) => createHash('sha256').update(buf).digest('hex');

test('a sealed record opens with the same master key and device id', () => {
  const master = randomBytes(32);
  const value = randomBytes(200);
  const sealed = sealSecret(master, 'SCN-004211', value);
  assert.equal(hashOf(openSecret(master, 'SCN-004211', sealed)), hashOf(value));
});

test('a record sealed for one device does not open for another', () => {
  const master = randomBytes(32);
  const sealed = sealSecret(master, 'SCN-004211', Buffer.from('depot-wifi-profile'));
  assert.throws(() => openSecret(master, 'SCN-004212', sealed));
});

test('a record does not open under another master key', () => {
  const sealed = sealSecret(randomBytes(32), 'PRN-000817', Buffer.from('label printer token'));
  assert.throws(() => openSecret(randomBytes(32), 'PRN-000817', sealed));
});

test('sealing the same value twice gives different records', () => {
  const master = randomBytes(32);
  const value = Buffer.from('same value');
  assert.notEqual(sealSecret(master, 'SGW-000031', value), sealSecret(master, 'SGW-000031', value));
});

test('a flipped bit anywhere in the record is rejected', () => {
  const master = randomBytes(32);
  const raw = Buffer.from(sealSecret(master, 'SCN-004211', Buffer.from('x'.repeat(64))), 'base64');
  for (const offset of [1, 13, 29, raw.length - 1]) {
    const copy = Buffer.from(raw);
    copy[offset] ^= 0x01;
    assert.throws(() => openSecret(master, 'SCN-004211', copy.toString('base64')), `offset ${offset}`);
  }
});

test('records with an unknown format byte are refused', () => {
  const master = randomBytes(32);
  const raw = Buffer.from(sealSecret(master, 'SCN-004211', Buffer.from('v')), 'base64');
  raw[0] = 9;
  assert.throws(() => openSecret(master, 'SCN-004211', raw.toString('base64')), /unknown format/);
});

test('the vault keeps records across restarts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vault-'));
  try {
    const master = randomBytes(32);
    const path = join(dir, 'vault.json');
    new Vault(path, master).put('SCN-004211', 'link', Buffer.from('shared'));
    const reopened = new Vault(path, master);
    assert.equal(reopened.get('SCN-004211', 'link').toString(), 'shared');
    assert.equal(reopened.get('SCN-009999', 'link'), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
