import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, KeyObject } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CeilingStore, PINNED_KEYS, familiesFor, filterProfile, pinnedKey, verifyEnvelope } from '../src/ceiling.ts';

function testKey(): { priv: KeyObject; rawHex: string } {
	const { privateKey, publicKey } = generateKeyPairSync('ed25519');
	const der = publicKey.export({ format: 'der', type: 'spki' });
	return { priv: privateKey, rawHex: der.subarray(der.length - 32).toString('hex') };
}

const signer = testKey();
const keys = [pinnedKey(signer.rawHex)];

function payload(version: number, platforms: Record<string, unknown> = {
	switch: ['.nintendo.net', '.nintendo.com', '.demonware.net'],
	wiiu: ['.nintendo.net', '.nintendowifi.net', '.openpak.org']
}): Buffer {
	return Buffer.from(JSON.stringify({ type: 'openpak-ceiling', version, issued: '2026-09-24T10:30:00Z', platforms, extra: 'ignored' }));
}

function envelope(body: Buffer, by = signer, keyid = pinnedKey(by.rawHex).keyid): Buffer {
	return Buffer.from(JSON.stringify({
		payload: body.toString('base64'),
		signatures: [{ keyid, sig: sign(null, body, by.priv).toString('base64') }]
	}));
}

test('pinned production key is well formed', () => {
	assert.equal(PINNED_KEYS[0].keyid, '36e8bcdd93c2c1a1d7e5d87bbba05a7a4f97882131cf6878f1c053a25a377fe4');
	const raw = Buffer.from('D9KiZgho5T0g/IEePxVxDLGtFXun2oAZ96WeitYE2Hw=', 'base64');
	assert.equal(createHash('sha256').update(raw).digest('hex'), PINNED_KEYS[0].keyid);
});

test('good envelope verifies; ceiling is the union of served platforms', () => {
	const ceiling = verifyEnvelope(envelope(payload(3)), keys);
	assert.equal(ceiling.version, 3);
	assert.deepEqual(familiesFor(ceiling), ['.demonware.net', '.nintendo.com', '.nintendo.net', '.nintendowifi.net', '.openpak.org']);
	assert.deepEqual(familiesFor(ceiling, ['wiiu']), ['.nintendo.net', '.nintendowifi.net', '.openpak.org']);
});

test('tampered payload is rejected', () => {
	const env = JSON.parse(envelope(payload(3)).toString());
	env.payload = payload(3, { switch: ['.evil.com'] }).toString('base64');
	assert.throws(() => verifyEnvelope(Buffer.from(JSON.stringify(env)), keys), /bad signature/);
});

test('unknown key is rejected', () => {
	const other = testKey();
	// Unknown keyid.
	assert.throws(() => verifyEnvelope(envelope(payload(3), other), keys), /unknown key/);
	// Pinned keyid, but signed by another key.
	assert.throws(() => verifyEnvelope(envelope(payload(3), other, keys[0].keyid), keys), /bad signature/);
});

test('malformed files are rejected', () => {
	assert.throws(() => verifyEnvelope(Buffer.from('not json'), keys), /malformed/);
	assert.throws(() => verifyEnvelope(Buffer.from('{"payload":"%%%","signatures":[]}'), keys), /malformed/);
	const wrongType = Buffer.from(JSON.stringify({ type: 'other', version: 1, platforms: {} }));
	assert.throws(() => verifyEnvelope(envelope(wrongType), keys), /malformed: type/);
	assert.throws(() => verifyEnvelope(envelope(payload(0)), keys), /malformed: version/);
	assert.throws(() => verifyEnvelope(envelope(payload(1, { switch: ['.Nintendo.net'] })), keys), /malformed: family/);
	assert.throws(() => verifyEnvelope(envelope(payload(1, { switch: ['nintendo.net'] })), keys), /malformed: family/);
	assert.throws(() => verifyEnvelope(envelope(payload(1, { switch: '.nintendo.net' })), keys), /malformed: platform/);
	assert.throws(() => verifyEnvelope(envelope(Buffer.from('not json')), keys), /malformed: payload/);
});

test('a one-label family rejects the whole file', () => {
	assert.throws(() => verifyEnvelope(envelope(payload(4, { switch: ['.nintendo.net', '.com'] })), keys), /malformed: family ".com"/);
	assert.throws(() => verifyEnvelope(envelope(payload(4, { ds: ['.'] })), keys), /malformed/);
});

test('rollback is refused and the highest version persists', () => {
	const dir = mkdtempSync(join(tmpdir(), 'ceiling-'));
	const store = new CeilingStore(dir, keys);
	const v3 = envelope(payload(3));
	store.accept(v3);
	assert.equal(store.highest(), 3);
	assert.throws(() => store.accept(envelope(payload(2))), /rollback/);
	assert.equal(store.current?.version, 3);
	store.accept(v3); // same version is fine
	store.accept(envelope(payload(5)));

	// Restart: a fresh store sees the persisted number and the cache.
	const restarted = new CeilingStore(dir, keys);
	assert.equal(restarted.highest(), 5);
	assert.equal(restarted.loadCached().version, 5);
	assert.throws(() => restarted.accept(envelope(payload(4))), /rollback/);
});

test('cache holds the exact bytes, 0600, and is re-verified on load', () => {
	const dir = mkdtempSync(join(tmpdir(), 'ceiling-'));
	const store = new CeilingStore(dir, keys);
	const bytes = Buffer.concat([envelope(payload(7)), Buffer.from('\n')]);
	store.accept(bytes);
	assert.deepEqual(readFileSync(join(dir, 'ceiling.json')), bytes);
	assert.equal(statSync(join(dir, 'ceiling.json')).mode & 0o777, 0o600);

	const env = JSON.parse(bytes.toString());
	env.payload = payload(8, { switch: ['.evil.com'] }).toString('base64');
	writeFileSync(join(dir, 'ceiling.json'), JSON.stringify(env));
	assert.throws(() => new CeilingStore(dir, keys).loadCached(), /bad signature/);
	assert.throws(() => new CeilingStore(join(dir, 'missing'), keys).loadCached(), /no cached ceiling/);
});

test('names outside the ceiling are dropped one by one, never the whole profile', () => {
	const families = familiesFor(verifyEnvelope(envelope(payload(3)), keys));
	const out = filterProfile(
		['.nintendo.net', '.account.nintendo.com', '.battle.net', '.com', 42],
		['nintendo.net', 'x.demonware.net', 'evil.example.org', 'openpak.org.evil.com', 'NNCS1.APP.NINTENDOWIFI.NET'],
		families
	);
	assert.deepEqual(out.suffixes, ['.nintendo.net', '.account.nintendo.com']);
	assert.deepEqual(out.exact, ['nintendo.net', 'x.demonware.net', 'nncs1.app.nintendowifi.net']);
	assert.deepEqual(out.dropped, ['family:.battle.net', 'family:.com', 'family:42', 'exact:evil.example.org', 'exact:openpak.org.evil.com']);
});
