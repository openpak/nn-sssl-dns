import DNS, { createServer, Packet } from 'dns2';
import { table } from 'table';
import colors from '@colors/colors';
import dotenv from 'dotenv';

process.on('SIGTERM', () => {
	process.exit();
});

dotenv.config();

const addressMap: Record<string, string> = {};

for (const variable in process.env) {
	if (variable.startsWith('SSSL_DNS_MAP')) {
		const hostname = variable.split('SSSL_DNS_MAP_')[1];
		const address = process.env[variable]!;

		addressMap[hostname] = address;
	}
}

if (!addressMap['conntest.nintendowifi.net']) {
	if (!process.env.SSSL_DNS_DEFAULT_ADDRESS) {
		console.log(colors.bgRed('Mapping for conntest.nintendowifi.net not found and no default address set. Set either SSSL_DNS_DEFAULT_ADDRESS or SSSL_DNS_MAP_conntest.nintendowifi.net'));
		process.exit();
	}

	addressMap['conntest.nintendowifi.net'] = process.env.SSSL_DNS_DEFAULT_ADDRESS;
}

if (!addressMap['account.nintendo.net']) {
	if (!process.env.SSSL_DNS_DEFAULT_ADDRESS) {
		console.log(colors.bgRed('Mapping for account.nintendo.net not found and no default address set. Set either SSSL_DNS_DEFAULT_ADDRESS or SSSL_DNS_MAP_account.nintendo.net'));
		process.exit();
	}

	addressMap['account.nintendo.net'] = process.env.SSSL_DNS_DEFAULT_ADDRESS;
}

let udpPort = 0;
let tcpPort = 0;

if (process.env.SSSL_UDP_PORT) {
	udpPort = Number(process.env.SSSL_UDP_PORT);
}

if (process.env.SSSL_TCP_PORT) {
	tcpPort = Number(process.env.SSSL_TCP_PORT);
}

if (Number.isNaN(udpPort)) {
	console.log(colors.bgRed('Invalid UDP port'));
	process.exit();
}

if (Number.isNaN(tcpPort)) {
	console.log(colors.bgRed('Invalid TCP port'));
	process.exit();
}

if (udpPort === 0 && tcpPort === 0) {
	console.log(colors.bgRed('No server port set. Set one of SSSL_UDP_PORT or SSSL_TCP_PORT'));
	process.exit();
}

if (udpPort === tcpPort) {
	console.log(colors.bgRed('UDP and TCP ports cannot match'));
	process.exit();
}

if (udpPort === 0) {
	console.log(colors.bgYellow('UDP port not set. One will be randomly assigned'));
}

if (tcpPort === 0) {
	console.log(colors.bgYellow('TCP port not set. One will be randomly assigned'));
}

// OpenPak (NP-4): the families this resolver answers are the same list the
// emulators read — GET /api/v1/network/profile on the website, fetched on
// boot and re-fetched on the profile's own recheck_after hint. Until the
// first fetch lands, and again whenever the website stops answering, the
// compiled-in list below is the truth (stale beats broken: a console must
// never lose its name server because a profile fetch failed).
const OURS_FALLBACK = ['.nintendo.net', '.nintendowifi.net', '.nintendo.com', '.openpak.org', '.gamespy.com'];
let oursSuffixes = OURS_FALLBACK;
let oursExact: string[] = [];
let recheckAfter = 6 * 3600; // seconds; replaced by the profile's own hint
const NETPROFILE_URL = process.env.NETPROFILE_URL || 'http://127.0.0.1:20010/api/v1/network/profile';

// A console whose only network setting is a DNS server has nowhere else to
// go, so this resolver answers every name the profile names — including ones
// the profile lists under redirect.never. That list exists for clients with
// a working resolution path of their own (emulators): a connection test
// pointed at OpenPak measures OpenPak. Here the alternative to answering
// conntest is forwarding it to a corpse, and the console has no second
// resolver to fall back to. OpenPak's answer IS the service.
interface NetworkProfile {
	version?: number;
	server?: { address?: string };
	redirect?: { suffixes?: unknown; exact?: unknown };
	recheck_after?: number;
}

async function fetchProfile(): Promise<void> {
	const res = await fetch(NETPROFILE_URL, { signal: AbortSignal.timeout(2000) });
	if (!res.ok) {
		throw new Error(`profile fetch answered ${res.status}`);
	}
	const profile = await res.json() as NetworkProfile;
	const suffixes = profile.redirect?.suffixes;
	const exact = profile.redirect?.exact;
	// Reject the whole profile rather than apply part of it: a malformed
	// answer is a fallback, never a half-applied resolver.
	if (!Array.isArray(suffixes) || !suffixes.every(s => typeof s === 'string' && s.startsWith('.')) ||
		!Array.isArray(exact) || !exact.every(s => typeof s === 'string')) {
		throw new Error('profile carries malformed redirect lists');
	}
	oursSuffixes = suffixes as string[];
	oursExact = exact as string[];
	if (typeof profile.recheck_after === 'number' && profile.recheck_after > 0) {
		recheckAfter = profile.recheck_after;
	}
	console.log(colors.green(`network profile applied: version ${profile.version ?? '?'}, ${oursSuffixes.length} families, ${oursExact.length} exact names, recheck ${recheckAfter}s`));
}

// One fetch at boot (fallback covers failure), then the profile's own hint.
// A list that changes a few times a month does not want a push channel; a
// missed refresh only means the console keeps yesterday's correct answer.
async function profileLoop(): Promise<void> {
	try {
		await fetchProfile();
	} catch (err) {
		console.log(colors.yellow(`network profile unavailable; keeping the compiled-in list (${String(err)})`));
	}
	const tick = (): void => {
		fetchProfile().catch(() => { /* the last good list is already serving */ });
	};
	setInterval(tick, Math.max(recheckAfter, 60) * 1000).unref();
}

const DEFAULT_ADDRESS = process.env.SSSL_DNS_DEFAULT_ADDRESS;
const upstream = new DNS({ nameServers: [ process.env.SSSL_DNS_UPSTREAM || '1.1.1.1' ] });

function ours(name: string): string | undefined {
	if (addressMap[name]) {
		return addressMap[name];
	}
	const lower = name.toLowerCase();
	if (!DEFAULT_ADDRESS) {
		return undefined;
	}
	if (oursSuffixes.some(suffix => lower.endsWith(suffix)) || oursExact.includes(lower)) {
		return DEFAULT_ADDRESS;
	}
	return undefined;
}

// OpenPak: this resolver is reachable from the internet, because a console's DNS setting is
// the only one it has. That makes it an amplification target, so: a token bucket per client
// address, and ANY queries are refused outright (they are the classic amplification vector and
// no console sends them). Buckets are swept so a scan cannot grow the map without bound.
const RATE_PER_SECOND = Number(process.env.SSSL_DNS_RATE || 15);
const RATE_BURST = Number(process.env.SSSL_DNS_BURST || 45);
type Bucket = { tokens: number; last: number };
const buckets = new Map<string, Bucket>();

function allowed(client: string): boolean {
	const now = Date.now();
	const bucket = buckets.get(client) ?? { tokens: RATE_BURST, last: now };
	bucket.tokens = Math.min(RATE_BURST, bucket.tokens + ((now - bucket.last) / 1000) * RATE_PER_SECOND);
	bucket.last = now;
	if (bucket.tokens < 1) {
		buckets.set(client, bucket);
		return false;
	}
	bucket.tokens -= 1;
	buckets.set(client, bucket);
	return true;
}

setInterval(() => {
	const cutoff = Date.now() - 60_000;
	for (const [ client, bucket ] of buckets) {
		if (bucket.last < cutoff) {
			buckets.delete(client);
		}
	}
}, 60_000).unref();

const server = createServer({
	udp: true,
	tcp: true,
	handle: async (request, send, rinfo) => {
		const [ question ] = request.questions;
		const { name } = question;
		const qtype = (question as { type?: number }).type ?? Packet.TYPE.A;
		const response = Packet.createResponseFromRequest(request);

		// 255 is ANY: refused, never forwarded.
		if (qtype === 255) {
			return;
		}
		const client = (rinfo as { address?: string } | undefined)?.address;
		if (client && !allowed(client)) {
			return; // silently dropped: an answer is itself the amplification
		}
		const address = ours(name);
		if (address) {
			if (qtype === Packet.TYPE.A) {
				response.answers.push({
					name,
					type: Packet.TYPE.A,
					class: Packet.CLASS.IN,
					ttl: 300,
					address
				});
			}
			send(response);
			return;
		}
		try {
			const answer = await upstream.resolve(name, typeName(qtype) as never);
			response.answers = answer.answers;
		} catch {
			// no answer is what a dead upstream gives too
		}
		send(response);
	}
});

function typeName(type: number): string {
	for (const [ key, value ] of Object.entries(Packet.TYPE)) {
		if (value === type) {
			return key;
		}
	}
	return 'A';
}

server.on('listening', () => {
	const tableConfig = {
		border: {
			topBody: '─',
			topJoin: '┬',
			topLeft: '┌',
			topRight: '┐',

			bottomBody: '─',
			bottomJoin: '┴',
			bottomLeft: '└',
			bottomRight: '┘',

			bodyLeft: '│',
			bodyRight: '│',
			bodyJoin: '│',

			joinBody: '─',
			joinLeft: '├',
			joinRight: '┤',
			joinJoin: '┼'
		}
	};

	const addresses = server.addresses();
	const tableData = [
		[colors.cyan('Protocol'), colors.cyan('Address')]
	];

	if (addresses.udp) {
		tableData.push([
			colors.green('UDP'), colors.green(`${addresses.udp.address}:${addresses.udp.port}`)
		]);
	}

	if (addresses.tcp) {
		tableData.push([
			colors.green('TCP'), colors.green(`${addresses.tcp.address}:${addresses.tcp.port}`)
		]);
	}

	console.log(colors.green('SSSL-DNS listening on the following addresses'));
	console.log(table(tableData, tableConfig));
});

// SSSL_BIND_ADDRESS: bind one interface (a host with systemd-resolved on 127.0.0.53 cannot take 0.0.0.0:53).
const bindAddress = process.env.SSSL_BIND_ADDRESS || '0.0.0.0';
server.listen({
	udp: udpPort !== 0 ? { port: udpPort, address: bindAddress } : undefined,
	tcp: tcpPort !== 0 ? { port: tcpPort, address: bindAddress } : undefined
} as never); // dns2 accepts { port, address } at runtime; its typings only know a port

void profileLoop();
