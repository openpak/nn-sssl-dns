import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import dns2 from 'dns2';
import {
	NegativeCache, RCODE, RateLimiter, configFromEnv, createHandler, newStats, prefixKey, preserveEdnsSize, udpLimit, udpUpstream,
	type GuardConfig, type Pkt, type Upstream, type UpstreamAnswer
} from '../src/guard.ts';

const { Packet } = dns2 as unknown as { Packet: Pkt };
preserveEdnsSize(Packet);

const OURS = '192.0.2.10';
const NNCS2 = '192.0.2.20';
const map: Record<string, string> = { 'nncs2.app.nintendowifi.net': NNCS2 };
function ours(name: string): string | undefined {
	if (map[name]) {
		return map[name];
	}
	const lower = name.toLowerCase();
	return [ '.nintendo.net', '.nintendowifi.net', '.openpak.org' ].some(s => lower.endsWith(s)) ? OURS : undefined;
}

const UDP = { address: '198.51.100.7', port: 5353, family: 'IPv4' };
const TCP = { remoteAddress: '198.51.100.7' };

function config(over: Partial<GuardConfig> = {}): GuardConfig {
	return { ...configFromEnv({}), ...over };
}

function setup(over: Partial<GuardConfig> = {}, upstream?: Upstream, now: () => number = Date.now) {
	const cfg = config(over);
	const stats = newStats();
	const calls: Array<[ string, number ]> = [];
	const up: Upstream = upstream ?? (async (name, type) => {
		calls.push([ name, type ]);
		return { rcode: 0, tc: false, answers: [ { name, type: 1, class: 1, ttl: 60, address: '203.0.113.5' } ] };
	});
	const handle = createHandler({
		Packet, config: cfg, ours, upstream: up, stats,
		limiter: new RateLimiter(cfg, now),
		negative: new NegativeCache(cfg.negativeTtl, 100, now)
	});
	async function ask(raw: Buffer, rinfo: unknown = UDP): Promise<Buffer | undefined> {
		let sent: Buffer | undefined;
		await handle(Packet.parse(raw), (r: Pkt) => { sent = r.toBuffer(); }, rinfo);
		return sent;
	}
	return { ask, stats, calls };
}

function query(name: string, type: number, opts: { edns?: number; cls?: number; opcode?: number } = {}): Buffer {
	const q = new Packet();
	q.header.id = 0x1234;
	q.header.rd = 1;
	if (opts.opcode) {
		q.header.opcode = opts.opcode;
	}
	q.questions.push({ name, type, class: opts.cls ?? 1 });
	if (opts.edns !== undefined) {
		const opt = Packet.Resource.EDNS([]);
		opt.class = opts.edns;
		q.additionals.push(opt);
	}
	return q.toBuffer();
}

const parse = (b: Buffer | undefined): Pkt => Packet.parse(b!);

// Query and answer bytes produced by the resolver before this change (old
// handler, dns2 2.1.0), for an OpenPak address of 192.0.2.10.
const GOLDEN: Array<[ string, string, string ]> = [
	[ 'A conntest', '12340100000100000000000008636f6e6e746573740c6e696e74656e646f77696669036e65740000010001',
		'12348100000100010000000008636f6e6e746573740c6e696e74656e646f77696669036e6574000001000108636f6e6e746573740c6e696e74656e646f77696669036e657400000100010000012c0004c000020a' ],
	[ 'A account with EDNS', '123401000001000000000001076163636f756e74086e696e74656e646f036e657400000100010000290200000000000000',
		'123481000001000100000000076163636f756e74086e696e74656e646f036e65740000010001076163636f756e74086e696e74656e646f036e657400000100010000012c0004c000020a' ],
	[ 'A nncs1', '123401000001000000000000056e6e637331036170700c6e696e74656e646f77696669036e65740000010001',
		'123481000001000100000000056e6e637331036170700c6e696e74656e646f77696669036e65740000010001056e6e637331036170700c6e696e74656e646f77696669036e657400000100010000012c0004c000020a' ],
	[ 'AAAA account (empty)', '123401000001000000000000076163636f756e74086e696e74656e646f036e657400001c0001',
		'123481000001000000000000076163636f756e74086e696e74656e646f036e657400001c0001' ],
	[ 'TXT conntest (empty, not refused)', '12340100000100000000000008636f6e6e746573740c6e696e74656e646f77696669036e65740000100001',
		'12348100000100000000000008636f6e6e746573740c6e696e74656e646f77696669036e65740000100001' ]
];

test('Nintendo-name answers are byte-identical to the old resolver', async () => {
	for (const [ label, q, a ] of GOLDEN) {
		for (const rinfo of [ UDP, TCP ]) {
			const { ask, calls } = setup();
			const out = await ask(Buffer.from(q, 'hex'), rinfo);
			assert.equal(out?.toString('hex'), a, label);
			assert.equal(calls.length, 0, `${label}: never recursed`);
		}
	}
});

test('nncs2 keeps its explicit mapping, never the default address', async () => {
	const { ask } = setup();
	const res = parse(await ask(query('nncs2.app.nintendowifi.net', 1)));
	assert.equal(res.answers[0].address, NNCS2);
});

test('ANY is refused for every name, with the question only', async () => {
	for (const name of [ 'conntest.nintendowifi.net', 'example.com' ]) {
		const { ask, stats, calls } = setup();
		const raw = query(name, 255);
		const out = await ask(raw);
		const res = parse(out);
		assert.equal(res.header.rcode, RCODE.REFUSED);
		assert.equal(res.answers.length + res.authorities.length + res.additionals.length, 0);
		assert.equal(out!.length, raw.length, 'no amplification');
		assert.equal(stats.refusedType, 1);
		assert.equal(calls.length, 0);
	}
});

test('amplification-prone types are refused on recursion', async () => {
	for (const type of [ 16, 43, 46, 48, 50, 252, 251 ]) {
		const { ask, calls } = setup();
		assert.equal(parse(await ask(query('example.com', type))).header.rcode, RCODE.REFUSED, `type ${type}`);
		assert.equal(calls.length, 0);
	}
});

test('non-IN class and non-QUERY opcode are refused', async () => {
	const { ask, calls } = setup();
	assert.equal(parse(await ask(query('version.bind', 16, { cls: 3 }))).header.rcode, RCODE.REFUSED);
	assert.equal(parse(await ask(query('example.com', 1, { cls: 3 }))).header.rcode, RCODE.REFUSED);
	assert.equal(parse(await ask(query('example.com', 1, { opcode: 2 }))).header.rcode, RCODE.NOTIMP);
	assert.equal(calls.length, 0);
});

test('console types are recursed', async () => {
	for (const type of [ 1, 28, 5, 33, 15, 12, 2, 6 ]) {
		const { ask, calls } = setup();
		const res = parse(await ask(query('example.com', type)));
		assert.equal(res.header.rcode, RCODE.NOERROR);
		assert.deepEqual(calls, [ [ 'example.com', type ] ]);
	}
});

test('recursive answers carry the answer section only, and keep the upstream rcode', async () => {
	const upstream: Upstream = async () => ({ rcode: RCODE.NXDOMAIN, tc: false, answers: [] });
	const { ask } = setup({}, upstream);
	const res = parse(await ask(query('nope.example', 1)));
	assert.equal(res.header.rcode, RCODE.NXDOMAIN);
	assert.equal(res.authorities.length, 0);
	assert.equal(res.additionals.length, 0);
});

function many(n: number): Upstream {
	return async name => ({
		rcode: 0, tc: false,
		answers: Array.from({ length: n }, (_, i) => ({ name, type: 1, class: 1, ttl: 60, address: `203.0.113.${i % 250}` }))
	});
}

test('UDP answers fit 512 without EDNS, else TC=1 and empty', async () => {
	const { ask, stats } = setup({}, many(40)); // 40 x 31 bytes > 512
	const res = parse(await ask(query('big.example', 1)));
	assert.equal(res.header.tc, 1);
	assert.equal(res.answers.length, 0);
	assert.equal(stats.truncated, 1);
	const small = setup({}, many(5));
	const ok = parse(await small.ask(query('big.example', 1)));
	assert.equal(ok.header.tc, 0);
	assert.equal(ok.answers.length, 5);
});

test('the client EDNS size is clamped to 1232 and we advertise 1232', async () => {
	// 50 answers ~ 1.6 KB: over 1232 even though the client asked for 4096.
	const big = setup({}, many(50));
	const out = await big.ask(query('big.example', 1, { edns: 4096 }));
	const res = parse(out);
	assert.equal(res.header.tc, 1);
	assert.ok(out!.length <= 1232);
	// 30 answers ~ 1 KB: fits 1232, not 512.
	const mid = setup({}, many(30));
	const midOut = await mid.ask(query('big.example', 1, { edns: 4096 }));
	const midRes = parse(midOut);
	assert.equal(midRes.header.tc, 0);
	assert.equal(midRes.answers.length, 30);
	assert.ok(midOut!.length > 512 && midOut!.length <= 1232);
	assert.equal(midRes.additionals.length, 1);
	assert.equal(midRes.additionals[0].type, 41);
	assert.equal(midOut!.readUInt16BE(midOut!.length - 8), 1232, 'advertised UDP size');
	// The same answer over TCP is not truncated.
	const tcp = setup({}, many(50));
	assert.equal(parse(await tcp.ask(query('big.example', 1, { edns: 4096 }), TCP)).answers.length, 50);
});

test('udpLimit reads the preserved OPT size', () => {
	assert.deepEqual(udpLimit(parse(query('a.example', 1)), 1232), { limit: 512, edns: false });
	assert.deepEqual(udpLimit(parse(query('a.example', 1, { edns: 1400 })), 1232), { limit: 1232, edns: true });
	assert.deepEqual(udpLimit(parse(query('a.example', 1, { edns: 800 })), 1232), { limit: 800, edns: true });
	assert.deepEqual(udpLimit(parse(query('a.example', 1, { edns: 100 })), 1232), { limit: 512, edns: true });
});

test('prefix keys: /24 IPv4, /56 IPv6, mapped IPv4 as IPv4', () => {
	assert.equal(prefixKey('198.51.100.7'), '198.51.100.0/24');
	assert.equal(prefixKey('198.51.100.250'), '198.51.100.0/24');
	assert.equal(prefixKey('::ffff:198.51.100.7'), '198.51.100.0/24');
	assert.equal(prefixKey('255.255.255.255'), '255.255.255.0/24');
	assert.equal(prefixKey('2001:db8:1234:5678:9abc::1'), '2001:db8:1234:5600:0:0:0:0/56');
	assert.equal(prefixKey('2001:db8:1234:56ff::2'), '2001:db8:1234:5600:0:0:0:0/56');
	assert.equal(prefixKey('::1'), '0:0:0:0:0:0:0:0/56');
	assert.equal(prefixKey('10.1.2.3', 32), '10.1.2.3/32');
});

test('rate limit: a console boot passes, a flood drops with every 2nd slipped as TC=1', async () => {
	let now = 1_000_000;
	const { ask, stats } = setup({ rate: 20, burst: 200, slip: 2 }, undefined, () => now);
	// A boot: a few dozen names in one go.
	for (let i = 0; i < 60; i++) {
		const res = parse(await ask(query('account.nintendo.net', 1)));
		assert.equal(res.answers.length, 1);
	}
	for (let i = 0; i < 140; i++) {
		await ask(query('account.nintendo.net', 1), { address: `198.51.100.${i % 250}`, port: 1 });
	}
	// Bucket of 198.51.100.0/24 is empty now.
	const outs = [];
	for (let i = 0; i < 4; i++) {
		outs.push(await ask(query('account.nintendo.net', 1)));
	}
	assert.equal(outs.filter(o => o === undefined).length, 2);
	for (const out of outs.filter(o => o !== undefined)) {
		const res = parse(out);
		assert.equal(res.header.tc, 1);
		assert.equal(res.answers.length, 0);
	}
	assert.equal(stats.rateLimitedDropped, 2);
	assert.equal(stats.rateLimitedSlipped, 2);
	// Another /24 has its own bucket.
	assert.ok(await ask(query('account.nintendo.net', 1), { address: '198.51.101.1', port: 1 }));
	// TCP is never limited.
	assert.equal(parse(await ask(query('account.nintendo.net', 1), TCP)).answers.length, 1);
	// One second refills 20 queries.
	now += 1000;
	for (let i = 0; i < 20; i++) {
		assert.equal(parse(await ask(query('account.nintendo.net', 1))).header.tc, 0);
	}
	assert.equal(await ask(query('account.nintendo.net', 1)), undefined);
});

test('rate limit: slip 0 drops everything over the limit', async () => {
	const { ask } = setup({ rate: 0, burst: 2, slip: 0 });
	assert.ok(await ask(query('a.openpak.org', 1)));
	assert.ok(await ask(query('a.openpak.org', 1)));
	for (let i = 0; i < 5; i++) {
		assert.equal(await ask(query('a.openpak.org', 1)), undefined);
	}
});

test('rate limiter bucket map is bounded and swept', () => {
	let now = 0;
	const limiter = new RateLimiter({ rate: 1, burst: 1, slip: 0, maxBuckets: 3 }, () => now);
	for (let i = 0; i < 10; i++) {
		limiter.check(`k${i}`);
	}
	assert.equal(limiter.size, 3);
	now += 120_000;
	limiter.sweep();
	assert.equal(limiter.size, 0);
});

test('negative cache: an upstream failure is SERVFAIL and is not retried for the TTL', async () => {
	let now = 0;
	let calls = 0;
	const upstream: Upstream = async () => {
		calls += 1;
		throw new Error('upstream timeout');
	};
	const { ask, stats } = setup({ negativeTtl: 30 }, upstream, () => now);
	assert.equal(parse(await ask(query('dead.example', 1))).header.rcode, RCODE.SERVFAIL);
	assert.equal(parse(await ask(query('DEAD.example', 1))).header.rcode, RCODE.SERVFAIL);
	assert.equal(calls, 1);
	assert.equal(stats.negativeCacheHits, 1);
	assert.equal(stats.upstreamFailed, 1);
	now += 31_000;
	await ask(query('dead.example', 1));
	assert.equal(calls, 2);
});

test('negative cache off with TTL 0', async () => {
	let calls = 0;
	const upstream: Upstream = async () => {
		calls += 1;
		return { rcode: RCODE.NXDOMAIN, tc: false, answers: [] } as UpstreamAnswer;
	};
	const { ask } = setup({ negativeTtl: 0 }, upstream);
	await ask(query('x.example', 1));
	await ask(query('x.example', 1));
	assert.equal(calls, 2);
});

test('a packet with no question or a response is ignored, not a crash', async () => {
	const { ask, stats } = setup();
	const empty = new Packet();
	empty.header.id = 1;
	assert.equal(await ask(empty.toBuffer()), undefined);
	const reply = Packet.parse(query('example.com', 1));
	reply.header.qr = 1;
	assert.equal(await ask(reply.toBuffer()), undefined);
	assert.equal(stats.malformed, 2);
});

test('configFromEnv defaults and overrides', () => {
	const d = configFromEnv({});
	assert.deepEqual(d, { rate: 20, burst: 200, slip: 2, ipv4Prefix: 24, ipv6Prefix: 56, maxUdp: 1232, negativeTtl: 30, upstreamTimeoutMs: 2000, maxBuckets: 100000, statsInterval: 3600 });
	const o = configFromEnv({ SSSL_DNS_RATE: '5', SSSL_DNS_MAX_UDP: '9000', SSSL_DNS_SLIP: 'x' });
	assert.equal(o.rate, 5);
	assert.equal(o.maxUdp, 4096);
	assert.equal(o.slip, 2);
});

test('udpUpstream: parses the answer, times out and closes on silence', async () => {
	const fake = createSocket('udp4');
	await new Promise<void>(resolve => fake.bind(0, '127.0.0.1', resolve));
	const port = fake.address().port;
	let silent = false;
	fake.on('message', (msg, rinfo) => {
		if (silent) {
			return;
		}
		const q = Packet.parse(msg);
		assert.equal(q.additionals[0].class, 1232, 'upstream query advertises 1232');
		const r = Packet.createResponseFromRequest(q);
		r.header.ra = 1;
		r.answers.push({ name: q.questions[0].name, type: 1, class: 1, ttl: 60, address: '203.0.113.9' });
		r.authorities.push({ name: 'example', type: 2, class: 1, ttl: 60, ns: 'ns.example' });
		fake.send(r.toBuffer(), rinfo.port, rinfo.address);
	});
	try {
		const up = udpUpstream(Packet, '127.0.0.1', port, 300);
		const a = await up('host.example', 1);
		assert.equal(a.rcode, 0);
		assert.equal(a.answers[0].address, '203.0.113.9');
		silent = true;
		await assert.rejects(up('host.example', 1), /timeout/);
	} finally {
		fake.close();
	}
});
