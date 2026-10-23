// OpenPak: the console resolver is an open resolver on the internet, because a
// console whose only network setting is a DNS server has no other one. This
// file is everything that keeps it from being an amplifier:
//
//   - response-rate limiting per source prefix (/24 IPv4, /56 IPv6) on UDP,
//     with BIND-style "slip": most over-limit queries are dropped, every Nth
//     gets a truncated (TC=1, empty) answer so a real client behind an abused
//     prefix can retry over TCP. TCP is never limited: it cannot be spoofed.
//   - ANY, zone transfers, DNSSEC records and TXT are refused on recursion
//     (REFUSED, question echoed, nothing else). Nintendo names keep today's
//     answers byte for byte; only ANY on them is refused.
//   - recursive answers carry the answer section only, and over UDP fit the
//     client's EDNS size clamped to 1232 bytes (512 without EDNS), else TC=1.
//   - a short negative cache for upstream failures and NXDOMAIN.
//   - aggregate counters; no client address is ever logged.
//
// Kept free of third-party imports (dns2's Packet is passed in) so the tests
// run against it directly.

import { createSocket } from 'node:dgram';
import { isIPv4, isIPv6 } from 'node:net';

export const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 } as const;

const TYPE_A = 1;
const TYPE_OPT = 41;
const TYPE_ANY = 255;
const CLASS_IN = 1;

// Recursion refuses these. Consoles (Wii U, 3DS, Wii, DS, PS3) ask for A and
// nothing else in every trace we have; AAAA, CNAME, SRV, MX, PTR, NS, SOA,
// CAA, HTTPS/SVCB stay allowed for anything else that points at us.
export const REFUSED_TYPES: ReadonlyMap<number, string> = new Map([
	[ 10, 'NULL' ],
	[ 16, 'TXT' ],
	[ 43, 'DS' ],
	[ 46, 'RRSIG' ],
	[ 47, 'NSEC' ],
	[ 48, 'DNSKEY' ],
	[ 50, 'NSEC3' ],
	[ 51, 'NSEC3PARAM' ],
	[ 59, 'CDS' ],
	[ 60, 'CDNSKEY' ],
	[ 99, 'SPF' ],
	[ 251, 'IXFR' ],
	[ 252, 'AXFR' ],
	[ 253, 'MAILB' ],
	[ 254, 'MAILA' ],
	[ 255, 'ANY' ]
]);

// Answer types dns2 can re-encode. An upstream record of any other type would
// serialise without its rdata, so it is left out (the client sees NODATA).
const ENCODABLE = new Set([ 1, 2, 5, 6, 12, 15, 16, 28, 33, 99, 257 ]);

export interface GuardConfig {
	rate: number; // tokens per second per prefix
	burst: number; // bucket size
	slip: number; // every Nth limited query gets TC=1; 0 = drop all
	ipv4Prefix: number;
	ipv6Prefix: number;
	maxUdp: number; // clamp for the client's EDNS size
	negativeTtl: number; // seconds; 0 disables
	upstreamTimeoutMs: number;
	maxBuckets: number;
	statsInterval: number; // seconds; 0 disables the periodic line
}

function envNumber(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
	const raw = env[name];
	if (raw === undefined || raw === '') {
		return fallback;
	}
	const value = Number(raw);
	return Number.isFinite(value) && value >= 0 ? value : fallback;
}

export function configFromEnv(env: NodeJS.ProcessEnv): GuardConfig {
	return {
		rate: envNumber(env, 'SSSL_DNS_RATE', 20),
		burst: envNumber(env, 'SSSL_DNS_BURST', 200),
		slip: envNumber(env, 'SSSL_DNS_SLIP', 2),
		ipv4Prefix: Math.min(32, envNumber(env, 'SSSL_DNS_IPV4_PREFIX', 24)),
		ipv6Prefix: Math.min(128, envNumber(env, 'SSSL_DNS_IPV6_PREFIX', 56)),
		maxUdp: Math.max(512, Math.min(4096, envNumber(env, 'SSSL_DNS_MAX_UDP', 1232))),
		negativeTtl: envNumber(env, 'SSSL_DNS_NEGATIVE_TTL', 30),
		upstreamTimeoutMs: envNumber(env, 'SSSL_DNS_UPSTREAM_TIMEOUT_MS', 2000),
		maxBuckets: envNumber(env, 'SSSL_DNS_MAX_BUCKETS', 100_000),
		statsInterval: envNumber(env, 'SSSL_DNS_STATS_INTERVAL', 3600)
	};
}

// The rate-limit key: a /24 (IPv4) or /56 (IPv6) prefix, so one attacker
// cannot dodge the limit by rotating through a block, and a household or a
// CGNAT pool shares one bucket (the default burst allows for that).
export function prefixKey(address: string, v4Bits = 24, v6Bits = 56): string {
	let addr = address;
	if (addr.startsWith('::ffff:') && isIPv4(addr.slice(7))) {
		addr = addr.slice(7);
	}
	if (isIPv4(addr)) {
		const n = addr.split('.').reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
		const mask = v4Bits === 0 ? 0 : (0xffffffff << (32 - v4Bits)) >>> 0;
		const masked = (n & mask) >>> 0;
		return `${[ 24, 16, 8, 0 ].map(shift => (masked >>> shift) & 0xff).join('.')}/${v4Bits}`;
	}
	if (isIPv6(addr)) {
		const groups = expandIPv6(addr);
		let bits = v6Bits;
		const out = groups.map(group => {
			const keep = Math.max(0, Math.min(16, bits));
			bits -= 16;
			return keep === 0 ? 0 : group & (0xffff << (16 - keep)) & 0xffff;
		});
		return `${out.map(g => g.toString(16)).join(':')}/${v6Bits}`;
	}
	return address;
}

function expandIPv6(addr: string): number[] {
	const zone = addr.indexOf('%');
	let a = zone >= 0 ? addr.slice(0, zone) : addr;
	// Trailing dotted quad (::ffff:1.2.3.4 that is not the mapped form, ::1.2.3.4).
	const lastColon = a.lastIndexOf(':');
	const tail = a.slice(lastColon + 1);
	if (isIPv4(tail)) {
		const o = tail.split('.').map(Number);
		a = `${a.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
	}
	const [ head, rest ] = a.split('::');
	const h = head ? head.split(':') : [];
	const r = rest !== undefined && rest !== '' ? rest.split(':') : [];
	const fill = rest === undefined ? [] : new Array(8 - h.length - r.length).fill('0');
	return [ ...h, ...fill, ...r ].map(g => parseInt(g, 16) || 0);
}

type Bucket = { tokens: number; last: number; limited: number };

export type RateVerdict = 'pass' | 'drop' | 'slip';

export class RateLimiter {
	private readonly buckets = new Map<string, Bucket>();
	private readonly overflow: Bucket;
	private readonly config: Pick<GuardConfig, 'rate' | 'burst' | 'slip' | 'maxBuckets'>;
	private readonly now: () => number;

	constructor(config: Pick<GuardConfig, 'rate' | 'burst' | 'slip' | 'maxBuckets'>, now: () => number = Date.now) {
		this.config = config;
		this.now = now;
		this.overflow = { tokens: config.burst, last: now(), limited: 0 };
	}

	get size(): number {
		return this.buckets.size;
	}

	check(key: string): RateVerdict {
		const now = this.now();
		let bucket = this.buckets.get(key);
		if (!bucket) {
			if (this.buckets.size >= this.config.maxBuckets) {
				// A spoofed sweep across many prefixes: everyone new shares one bucket
				// until the sweep below frees space.
				bucket = this.overflow;
			} else {
				bucket = { tokens: this.config.burst, last: now, limited: 0 };
				this.buckets.set(key, bucket);
			}
		}
		bucket.tokens = Math.min(this.config.burst, bucket.tokens + ((now - bucket.last) / 1000) * this.config.rate);
		bucket.last = now;
		if (bucket.tokens >= 1) {
			bucket.tokens -= 1;
			return 'pass';
		}
		bucket.limited += 1;
		if (this.config.slip > 0 && bucket.limited % this.config.slip === 0) {
			return 'slip';
		}
		return 'drop';
	}

	// Forget buckets idle long enough to have refilled.
	sweep(idleMs = 60_000): void {
		const cutoff = this.now() - idleMs;
		for (const [ key, bucket ] of this.buckets) {
			if (bucket.last < cutoff) {
				this.buckets.delete(key);
			}
		}
	}
}

export class NegativeCache {
	private readonly entries = new Map<string, { rcode: number; expires: number }>();
	private readonly ttlSeconds: number;
	private readonly maxEntries: number;
	private readonly now: () => number;

	constructor(ttlSeconds: number, maxEntries = 10_000, now: () => number = Date.now) {
		this.ttlSeconds = ttlSeconds;
		this.maxEntries = maxEntries;
		this.now = now;
	}

	get(name: string, type: number): number | undefined {
		if (this.ttlSeconds <= 0) {
			return undefined;
		}
		const key = `${name.toLowerCase()}/${type}`;
		const entry = this.entries.get(key);
		if (!entry) {
			return undefined;
		}
		if (entry.expires <= this.now()) {
			this.entries.delete(key);
			return undefined;
		}
		return entry.rcode;
	}

	set(name: string, type: number, rcode: number): void {
		if (this.ttlSeconds <= 0) {
			return;
		}
		if (this.entries.size >= this.maxEntries) {
			const oldest = this.entries.keys().next().value;
			if (oldest !== undefined) {
				this.entries.delete(oldest);
			}
		}
		this.entries.set(`${name.toLowerCase()}/${type}`, { rcode, expires: this.now() + this.ttlSeconds * 1000 });
	}
}

export interface Stats {
	queries: number;
	answeredOurs: number;
	recursed: number;
	rateLimitedDropped: number;
	rateLimitedSlipped: number;
	refusedType: number;
	refusedOther: number; // non-IN class, non-QUERY opcode
	malformed: number;
	truncated: number;
	upstreamFailed: number;
	negativeCacheHits: number;
}

export function newStats(): Stats {
	return { queries: 0, answeredOurs: 0, recursed: 0, rateLimitedDropped: 0, rateLimitedSlipped: 0, refusedType: 0, refusedOther: 0, malformed: 0, truncated: 0, upstreamFailed: 0, negativeCacheHits: 0 };
}

export function formatStats(stats: Stats): string {
	return Object.entries(stats).map(([ key, value ]) => `${key}=${value}`).join(' ');
}

// Loose shapes of dns2's parsed packets (its typings know almost nothing).
/* eslint-disable @typescript-eslint/no-explicit-any */
export type Pkt = any;
export interface PacketLib {
	createResponseFromRequest(request: Pkt): Pkt;
	parse(buffer: Buffer): Pkt;
	new (): Pkt;
	Resource: { EDNS(rdata: unknown[]): Pkt };
}

export interface UpstreamAnswer {
	rcode: number;
	tc: boolean;
	answers: Pkt[];
}

export type Upstream = (name: string, type: number) => Promise<UpstreamAnswer>;

// One UDP query to the upstream with a hard timeout; the socket is always
// closed (dns2's client never closes a socket whose answer does not come).
export function udpUpstream(Packet: PacketLib, server: string, port: number, timeoutMs: number): Upstream {
	return (name, type) => new Promise((resolve, reject) => {
		const query = new Packet();
		query.header.id = Math.floor(Math.random() * 0x10000);
		query.header.rd = 1;
		query.questions.push({ name, type, class: CLASS_IN });
		const opt = Packet.Resource.EDNS([]);
		opt.class = 1232;
		query.additionals.push(opt);
		const socket = createSocket(isIPv6(server) ? 'udp6' : 'udp4');
		const done = (err?: Error, value?: UpstreamAnswer): void => {
			clearTimeout(timer);
			socket.close();
			if (err) {
				reject(err);
			} else {
				resolve(value!);
			}
		};
		const timer = setTimeout(() => done(new Error('upstream timeout')), timeoutMs);
		socket.on('error', err => done(err));
		socket.on('message', message => {
			let parsed: Pkt;
			try {
				parsed = Packet.parse(message);
			} catch {
				return; // garbage: keep waiting for the real answer until the timeout
			}
			if (parsed.header.id !== query.header.id || !parsed.header.qr) {
				return;
			}
			done(undefined, { rcode: parsed.header.rcode, tc: !!parsed.header.tc, answers: parsed.answers ?? [] });
		});
		socket.send(query.toBuffer(), port, server, err => {
			if (err) {
				done(err);
			}
		});
	});
}

export interface Peer {
	transport: 'udp' | 'tcp';
	address?: string;
}

// dns2 hands UDP handlers the rinfo ({ address, port, family }) and TCP
// handlers the socket ({ remoteAddress, ... }).
export function peerOf(rinfo: unknown): Peer {
	const r = rinfo as { address?: unknown; remoteAddress?: unknown } | undefined;
	if (r && typeof r.remoteAddress === 'string') {
		return { transport: 'tcp', address: r.remoteAddress };
	}
	return { transport: 'udp', address: r && typeof r.address === 'string' ? r.address : undefined };
}

// The size a UDP answer may have: the client's EDNS size, at least 512,
// clamped to maxUdp; 512 for a client without EDNS. The request's OPT size is
// read from the raw class field (see preserveEdnsSize).
export function udpLimit(request: Pkt, maxUdp: number): { limit: number; edns: boolean } {
	const opt = (request.additionals ?? []).find((rr: Pkt) => rr && rr.type === TYPE_OPT);
	if (!opt) {
		return { limit: 512, edns: false };
	}
	const asked = typeof opt.class === 'number' ? opt.class : 512;
	return { limit: Math.min(Math.max(asked, 512), maxUdp), edns: true };
}

// dns2 overwrites an OPT record's class (the advertised UDP size) with 512
// on parse. Keep the value the client sent.
export function preserveEdnsSize(Packet: { Resource: { EDNS: { decode: (...args: any[]) => any } } }): void {
	const EDNS = Packet.Resource.EDNS as { decode: (...args: any[]) => any; preserved?: boolean };
	if (EDNS.preserved) {
		return;
	}
	const original = EDNS.decode;
	EDNS.decode = function (this: { class: number }, ...args: any[]): any {
		const sent = this.class;
		const result = original.apply(this, args);
		result.class = sent;
		return result;
	};
	EDNS.preserved = true;
}

export interface HandlerDeps {
	Packet: PacketLib;
	config: GuardConfig;
	ours: (name: string) => string | undefined;
	upstream: Upstream;
	limiter: RateLimiter;
	negative: NegativeCache;
	stats: Stats;
}

export type Send = (response: Pkt) => unknown;

function minimal(Packet: PacketLib, request: Pkt, rcode: number, tc = false): Pkt {
	const response = Packet.createResponseFromRequest(request);
	response.answers = [];
	response.authorities = [];
	response.additionals = [];
	response.header.rcode = rcode;
	response.header.tc = tc ? 1 : 0;
	return response;
}

export function createHandler(deps: HandlerDeps): (request: Pkt, send: Send, rinfo: unknown) => Promise<void> {
	const { Packet, config, ours, upstream, limiter, negative, stats } = deps;
	return async (request, send, rinfo) => {
		stats.queries += 1;
		const question = request?.questions?.[0];
		// No question, or a response sent at us (a reflection loop): nothing to answer.
		if (!question || typeof question.name !== 'string' || request.header?.qr) {
			stats.malformed += 1;
			return;
		}
		// Read the client's EDNS size now: dns2's createResponseFromRequest turns
		// the request object itself into the response and empties its additionals.
		const sizing = udpLimit(request, config.maxUdp);
		const peer = peerOf(rinfo);
		if (peer.transport === 'udp' && peer.address) {
			const verdict = limiter.check(prefixKey(peer.address, config.ipv4Prefix, config.ipv6Prefix));
			if (verdict === 'drop') {
				stats.rateLimitedDropped += 1;
				return;
			}
			if (verdict === 'slip') {
				stats.rateLimitedSlipped += 1;
				send(minimal(Packet, request, RCODE.NOERROR, true));
				return;
			}
		}

		const { name } = question;
		const qtype: number = question.type ?? TYPE_A;
		const qclass: number = question.class ?? CLASS_IN;

		// ANY is refused for every name, ours included (it was dropped before).
		if (qtype === TYPE_ANY) {
			stats.refusedType += 1;
			send(minimal(Packet, request, RCODE.REFUSED));
			return;
		}
		if ((request.header?.opcode ?? 0) !== 0) {
			stats.refusedOther += 1;
			send(minimal(Packet, request, RCODE.NOTIMP));
			return;
		}

		// Nintendo and OpenPak names: exactly the answer this resolver always gave.
		const address = ours(name);
		if (address) {
			stats.answeredOurs += 1;
			const response = Packet.createResponseFromRequest(request);
			if (qtype === TYPE_A) {
				response.answers.push({
					name,
					type: TYPE_A,
					class: CLASS_IN,
					ttl: 300,
					address
				});
			}
			send(response);
			return;
		}

		if (qclass !== CLASS_IN) {
			stats.refusedOther += 1;
			send(minimal(Packet, request, RCODE.REFUSED));
			return;
		}
		if (REFUSED_TYPES.has(qtype)) {
			stats.refusedType += 1;
			send(minimal(Packet, request, RCODE.REFUSED));
			return;
		}

		const cached = negative.get(name, qtype);
		if (cached !== undefined) {
			stats.negativeCacheHits += 1;
			send(minimal(Packet, request, cached));
			return;
		}

		stats.recursed += 1;
		let answer: UpstreamAnswer;
		try {
			answer = await upstream(name, qtype);
		} catch {
			stats.upstreamFailed += 1;
			negative.set(name, qtype, RCODE.SERVFAIL);
			send(minimal(Packet, request, RCODE.SERVFAIL));
			return;
		}
		if (answer.rcode === RCODE.SERVFAIL || answer.rcode === RCODE.NXDOMAIN || answer.rcode === RCODE.REFUSED) {
			if (answer.rcode === RCODE.SERVFAIL) {
				stats.upstreamFailed += 1;
			}
			negative.set(name, qtype, answer.rcode);
		}

		// Answer section only: no authority or additional records.
		const response = minimal(Packet, request, answer.rcode, answer.tc);
		response.header.ra = 1;
		response.answers = answer.answers.filter(rr => rr && ENCODABLE.has(rr.type) && rr.class === CLASS_IN);

		if (peer.transport === 'udp') {
			const { limit, edns } = sizing;
			if (edns) {
				const opt = Packet.Resource.EDNS([]);
				opt.name = '';
				opt.class = config.maxUdp; // what we advertise, never more than the clamp
				response.additionals = [ opt ];
			}
			if (response.toBuffer().length > limit) {
				stats.truncated += 1;
				response.answers = [];
				response.header.tc = 1;
			}
		}
		send(response);
	};
}
