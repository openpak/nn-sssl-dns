// OpenPak signed redirect ceiling (docs/signed-ceiling.md in the OpenPak
// workspace; copied to ../docs/signed-ceiling.md in this repo).
//
// The ceiling is the set of domain families this resolver may ever answer
// with the OpenPak address. It is an Ed25519-signed file whose key never
// touches the server, so a compromised box can change what the profile asks
// for but not widen what the resolver will actually redirect.
//
// Kept free of third-party imports so the tests run with no node_modules.

import { createHash, createPublicKey, verify, KeyObject } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export interface PinnedKey {
	keyid: string; // hex sha256 of the raw key
	key: KeyObject;
}

export interface Ceiling {
	version: number;
	platforms: Record<string, string[]>;
}

// Ed25519 SubjectPublicKeyInfo header; the raw 32-byte key follows it.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function pinnedKey(rawHex: string): PinnedKey {
	const raw = Buffer.from(rawHex, 'hex');
	if (raw.length !== 32) {
		throw new Error('Ed25519 public key must be 32 bytes');
	}
	return {
		keyid: createHash('sha256').update(raw).digest('hex'),
		key: createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
	};
}

// A list, so a future key can be pinned before the current one is retired.
export const PINNED_KEYS: PinnedKey[] = [
	pinnedKey('0fd2a2660868e53d20fc811e3f15710cb1ad157ba7da8019f7a59e8ad604d87c')
];

export const CEILING_URL = 'https://openpak.org/api/v1/network/ceiling';

// The platforms whose real consoles use this resolver. It answers the union
// profile, so its ceiling is the union of these platforms' families. ps3 covers
// real PS3s and Pier, whose emulated network hands the firmware this resolver.
export const SERVED_PLATFORMS = ['switch', 'wiiu', '3ds', 'wii', 'ds', 'ps3'];

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const LABEL = /^[a-z0-9_-]+$/;

export function validFamily(family: unknown): family is string {
	if (typeof family !== 'string' || !family.startsWith('.') || family !== family.toLowerCase()) {
		return false;
	}
	const labels = family.slice(1).split('.');
	return labels.length >= 2 && labels.every(label => LABEL.test(label));
}

// Verifies an envelope and returns its ceiling; throws with the reason.
// The signature covers the decoded payload bytes, which are then parsed as
// they are — never a re-serialisation.
export function verifyEnvelope(bytes: Buffer | string, keys: PinnedKey[] = PINNED_KEYS): Ceiling {
	let envelope: { payload?: unknown; signatures?: unknown };
	try {
		envelope = JSON.parse(bytes.toString());
	} catch {
		throw new Error('malformed: envelope is not JSON');
	}
	if (typeof envelope !== 'object' || envelope === null || typeof envelope.payload !== 'string' ||
		!BASE64.test(envelope.payload) || !Array.isArray(envelope.signatures)) {
		throw new Error('malformed: envelope needs payload and signatures');
	}
	const payload = Buffer.from(envelope.payload, 'base64');
	let known = false;
	let valid = false;
	for (const entry of envelope.signatures as { keyid?: unknown; sig?: unknown }[]) {
		const pinned = keys.find(k => typeof entry?.keyid === 'string' && k.keyid === entry.keyid.toLowerCase());
		if (!pinned || typeof entry.sig !== 'string' || !BASE64.test(entry.sig)) {
			continue;
		}
		known = true;
		if (verify(null, payload, pinned.key, Buffer.from(entry.sig, 'base64'))) {
			valid = true;
			break;
		}
	}
	if (!known) {
		throw new Error('unknown key: no signature by a pinned key');
	}
	if (!valid) {
		throw new Error('bad signature');
	}

	let body: { type?: unknown; version?: unknown; platforms?: unknown };
	try {
		body = JSON.parse(payload.toString('utf8'));
	} catch {
		throw new Error('malformed: payload is not JSON');
	}
	if (typeof body !== 'object' || body === null || body.type !== 'openpak-ceiling') {
		throw new Error('malformed: type is not openpak-ceiling');
	}
	if (typeof body.version !== 'number' || !Number.isInteger(body.version) || body.version < 1) {
		throw new Error('malformed: version is not a positive integer');
	}
	if (typeof body.platforms !== 'object' || body.platforms === null || Array.isArray(body.platforms)) {
		throw new Error('malformed: platforms is not an object');
	}
	const platforms: Record<string, string[]> = {};
	for (const [ platform, families ] of Object.entries(body.platforms as Record<string, unknown>)) {
		if (!Array.isArray(families)) {
			throw new Error(`malformed: platform ${platform} is not a list`);
		}
		for (const family of families) {
			if (!validFamily(family)) {
				throw new Error(`malformed: family ${JSON.stringify(family)} on ${platform}`);
			}
		}
		platforms[platform] = families as string[];
	}
	return { version: body.version, platforms };
}

export function familiesFor(ceiling: Ceiling, platforms: string[] = SERVED_PLATFORMS): string[] {
	const union = new Set<string>();
	for (const platform of platforms) {
		for (const family of ceiling.platforms[platform] ?? []) {
			union.add(family);
		}
	}
	return [...union].sort();
}

// A family covers its apex and everything below it.
function covered(name: string, families: string[]): boolean {
	return families.some(family => name === family.slice(1) || name.endsWith(family));
}

export interface Filtered {
	suffixes: string[];
	exact: string[];
	dropped: string[];
}

// Keeps every profile name inside the ceiling and drops the others one by
// one — never the whole profile.
export function filterProfile(suffixes: unknown[], exact: unknown[], families: string[]): Filtered {
	const out: Filtered = { suffixes: [], exact: [], dropped: [] };
	for (const suffix of suffixes) {
		if (typeof suffix === 'string' && suffix.startsWith('.') && covered(suffix.toLowerCase(), families)) {
			out.suffixes.push(suffix.toLowerCase());
		} else {
			out.dropped.push(`family:${String(suffix)}`);
		}
	}
	for (const name of exact) {
		if (typeof name === 'string' && !name.startsWith('.') && covered(name.toLowerCase(), families)) {
			out.exact.push(name.toLowerCase());
		} else {
			out.dropped.push(`exact:${String(name)}`);
		}
	}
	return out;
}

// On-disk state: the envelope bytes exactly as received and the highest
// version ever accepted (rollback protection).
export class CeilingStore {
	readonly dir: string;
	readonly keys: PinnedKey[];
	current?: Ceiling;

	constructor(dir: string, keys: PinnedKey[] = PINNED_KEYS) {
		this.dir = dir;
		this.keys = keys;
	}

	private get cachePath(): string {
		return join(this.dir, 'ceiling.json');
	}

	private get highestPath(): string {
		return join(this.dir, 'ceiling-highest-version');
	}

	highest(): number {
		try {
			const n = Number(readFileSync(this.highestPath, 'utf8').trim());
			return Number.isInteger(n) && n > 0 ? n : 0;
		} catch {
			return 0;
		}
	}

	// Loads and re-verifies the cached envelope; throws with the reason.
	loadCached(): Ceiling {
		let bytes: Buffer;
		try {
			bytes = readFileSync(this.cachePath);
		} catch {
			throw new Error('no cached ceiling');
		}
		const ceiling = verifyEnvelope(bytes, this.keys);
		if (ceiling.version < this.highest()) {
			throw new Error(`cached ceiling v${ceiling.version} is below the highest accepted v${this.highest()}`);
		}
		this.current = ceiling;
		return ceiling;
	}

	// Verifies fresh bytes, applies the rollback rule, then caches them
	// atomically. Throws with the reason; the previous ceiling stays.
	accept(bytes: Buffer): Ceiling {
		const ceiling = verifyEnvelope(bytes, this.keys);
		const highest = this.highest();
		if (ceiling.version < highest) {
			throw new Error(`rollback: v${ceiling.version} is below the highest accepted v${highest}`);
		}
		mkdirSync(this.dir, { recursive: true, mode: 0o700 });
		atomicWrite(this.cachePath, bytes);
		if (ceiling.version > highest) {
			atomicWrite(this.highestPath, Buffer.from(`${ceiling.version}\n`));
		}
		this.current = ceiling;
		return ceiling;
	}
}

function atomicWrite(path: string, bytes: Buffer): void {
	const tmp = `${path}.${process.pid}.tmp`;
	writeFileSync(tmp, bytes, { mode: 0o600 });
	renameSync(tmp, path);
}

export async function fetchCeilingBytes(url: string = CEILING_URL): Promise<Buffer> {
	// Plain fetch: public TLS trust, the pinned origin, never a URL from the profile.
	const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
	if (!res.ok) {
		throw new Error(`ceiling fetch answered ${res.status}`);
	}
	return Buffer.from(await res.arrayBuffer());
}
